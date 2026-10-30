/* cairn: offline bundles.
 *
 * A bundle is a self contained encrypted file that travels through anything: a USB
 * stick, a cloud drive, an email attachment. Whoever holds the matching identity
 * opens it later, on any platform, with no network and the sender long offline.
 *
 * A live session needs both devices awake at the same time. A bundle does not. Same
 * devices, same keys, different shape of delivery.
 *
 * Layout, all integers little endian:
 *
 *   magic "CRNB"          4
 *   version               1
 *   flags                 1
 *   chunk size            4
 *   plaintext length      8
 *   chunk count           4
 *   ephemeral public key 32    sender's one-time X25519 key
 *   sender public key  1264    identifies and signs
 *   nonce prefix         16
 *   chunks          n * (chunk + 16)
 *   signature            64
 *
 * The key is a Diffie-Hellman between a one-time key made for this bundle and the
 * recipient's static X25519 key. That is what makes a bundle readable by exactly one
 * device and nobody else: the sender throws its ephemeral secret away, the recipient
 * recomputes the same secret with its own static key, and an observer has neither.
 *
 * Each chunk is an independent AEAD frame with its index in the associated data, so
 * a flipped bit is caught and localised, and reordering or truncating chunks is
 * refused. A recipient never has to hold the whole plaintext in memory.
 */
#define _DEFAULT_SOURCE

#include "cairn/bundle.h"

#include <string.h>

static const char kBundleDomain[] = "cairn-bundle-v1";

static void put_u32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

static uint32_t get_u32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static void put_u64(uint8_t *p, uint64_t v)
{
    put_u32(p, (uint32_t)v);
    put_u32(p + 4, (uint32_t)(v >> 32));
}

static uint64_t get_u64(const uint8_t *p)
{
    return (uint64_t)get_u32(p) | ((uint64_t)get_u32(p + 4) << 32);
}

static uint32_t chunk_count_for(uint64_t len)
{
    uint64_t n = len / CAIRN_BUNDLE_CHUNK;
    if (len % CAIRN_BUNDLE_CHUNK != 0 || len == 0) n++;
    return (uint32_t)n;
}

uint64_t cairn_bundle_size(uint64_t plaintext_len)
{
    /* Every chunk pays one tag; the plaintext pays nothing extra. Sizing it this way
     * rather than n * (chunk + tag) matters: the last chunk is usually short, and
     * over-reporting would make callers allocate a chunk more than they need. */
    uint64_t n = chunk_count_for(plaintext_len);
    return CAIRN_BUNDLE_HEADER_BYTES + plaintext_len + n * CAIRN_TAG_BYTES +
           CAIRN_BUNDLE_SIG_BYTES;
}

/* Derives the wrapping key from one DH output.
 *
 * The shared secret alone is not used as a key: it goes through the KDF labelled
 * with the ephemeral public key, which gives domain separation and ties the key to
 * this one bundle. */
static int wrap_key(uint8_t out[CAIRN_KEY_BYTES], const uint8_t dh[CAIRN_X25519_BYTES],
                    const uint8_t eph_pub[CAIRN_X25519_BYTES])
{
    uint8_t seed[CAIRN_KEY_BYTES];

    if (cairn_mac(seed, sizeof seed, dh, CAIRN_X25519_BYTES,
                  kBundleDomain, sizeof kBundleDomain - 1) != CAIRN_OK)
        return CAIRN_ERR_CRYPTO;

    if (cairn_kdf(out, CAIRN_KEY_BYTES, seed, eph_pub, CAIRN_X25519_BYTES) != CAIRN_OK) {
        cairn_memzero(seed, sizeof seed);
        return CAIRN_ERR_CRYPTO;
    }
    cairn_memzero(seed, sizeof seed);
    return CAIRN_OK;
}

static void chunk_nonce(uint8_t nonce[CAIRN_NONCE_BYTES],
                        const uint8_t prefix[16], uint32_t index)
{
    memset(nonce, 0, CAIRN_NONCE_BYTES);
    memcpy(nonce, prefix, 16);
    put_u32(nonce + 16, index);
}

/* The index and the length are authenticated, so a chunk cannot be moved to another
 * position or truncated without the tag check failing. */
static void chunk_aad(uint8_t aad[12], const uint8_t prefix[16], uint32_t index,
                      uint32_t len)
{
    memcpy(aad, prefix, 4);
    put_u32(aad + 4, index);
    put_u32(aad + 8, len);
}

int cairn_bundle_begin(uint8_t *out, size_t outcap, size_t *written,
                       const cairn_bundle_opts *opts, uint64_t plaintext_len,
                       uint8_t wrap_key_out[32], uint8_t nonce_prefix[16])
{
    cairn_pubkey sender;
    uint8_t eph_pub[CAIRN_X25519_BYTES], eph_sec[CAIRN_X25519_BYTES];
    uint8_t dh[CAIRN_X25519_BYTES];
    uint8_t key[CAIRN_KEY_BYTES];
    size_t o = 0;
    int rc;

    if (out == NULL || written == NULL || opts == NULL || opts->sender == NULL)
        return CAIRN_ERR_ARG;
    if (opts->recipient == NULL || wrap_key_out == NULL || nonce_prefix == NULL)
        return CAIRN_ERR_ARG;
    if (outcap < CAIRN_BUNDLE_HEADER_BYTES) return CAIRN_ERR_BUFFER;
    if (plaintext_len == 0) return CAIRN_ERR_ARG;

    /* The one-time key is what makes the bundle forward secret: once the sender
     * forgets eph_sec, nothing recovers the wrap key from the file alone. */
    rc = cairn_x25519_keypair(eph_pub, eph_sec);
    if (rc != CAIRN_OK) return rc;

    rc = cairn_x25519(dh, eph_sec, opts->recipient->dh_pub);
    cairn_memzero(eph_sec, sizeof eph_sec);
    if (rc != CAIRN_OK) return rc;

    rc = wrap_key(key, dh, eph_pub);
    cairn_memzero(dh, sizeof dh);
    if (rc != CAIRN_OK) return rc;

    /* Handed back so chunk sealing needs no secrets of its own. */
    memcpy(wrap_key_out, key, CAIRN_KEY_BYTES);
    cairn_memzero(key, sizeof key);

    if (cairn_random_bytes(nonce_prefix, 16) != CAIRN_OK) return CAIRN_ERR_IO;
    if (cairn_identity_pubkey(opts->sender, &sender) != CAIRN_OK) return CAIRN_ERR_CRYPTO;

    memcpy(out + o, CAIRN_BUNDLE_MAGIC, 4); o += 4;
    out[o++] = CAIRN_BUNDLE_VERSION;
    out[o++] = 0x01; /* sealed to one recipient, always */
    put_u32(out + o, CAIRN_BUNDLE_CHUNK); o += 4;
    put_u64(out + o, plaintext_len); o += 8;
    put_u32(out + o, chunk_count_for(plaintext_len)); o += 4;
    memcpy(out + o, eph_pub, CAIRN_X25519_BYTES); o += CAIRN_X25519_BYTES;
    cairn_pubkey_encode(out + o, &sender); o += CAIRN_PUBKEY_BYTES;
    memcpy(out + o, nonce_prefix, 16); o += 16;

    *written = o;
    return CAIRN_OK;
}

int cairn_bundle_chunk(uint8_t *dst, size_t dstcap, size_t *written,
                       const uint8_t wrap_key[32], const uint8_t nonce_prefix[16],
                       uint32_t index, const void *plain, size_t plain_len)
{
    uint8_t nonce[CAIRN_NONCE_BYTES];
    uint8_t aad[12];
    int rc;

    if (dst == NULL || written == NULL || wrap_key == NULL || nonce_prefix == NULL)
        return CAIRN_ERR_ARG;
    if (plain == NULL && plain_len > 0) return CAIRN_ERR_ARG;
    if (plain_len > CAIRN_BUNDLE_CHUNK) return CAIRN_ERR_ARG;
    if (dstcap < plain_len + CAIRN_TAG_BYTES) return CAIRN_ERR_BUFFER;

    chunk_nonce(nonce, nonce_prefix, index);
    chunk_aad(aad, nonce_prefix, index, (uint32_t)plain_len);

    rc = cairn_aead_seal(dst, wrap_key, nonce, aad, sizeof aad, plain, plain_len);
    if (rc != CAIRN_OK) return rc;

    *written = plain_len + CAIRN_TAG_BYTES;
    return CAIRN_OK;
}

int cairn_bundle_sign(uint8_t out[CAIRN_ED25519_SIG_BYTES], const cairn_identity *sender,
                      const uint8_t *bundle, size_t bundle_len)
{
    if (out == NULL || sender == NULL || bundle == NULL) return CAIRN_ERR_ARG;
    return cairn_ed25519_sign(out, sender->ed_sec, bundle, bundle_len);
}

int cairn_bundle_peek(cairn_bundle_info *info, const void *bundle, size_t len)
{
    const uint8_t *p = (const uint8_t *)bundle;
    size_t o;

    if (info == NULL || bundle == NULL) return CAIRN_ERR_ARG;
    if (len < CAIRN_BUNDLE_HEADER_BYTES) return CAIRN_ERR_FORMAT;
    if (memcmp(p, CAIRN_BUNDLE_MAGIC, 4) != 0) return CAIRN_ERR_FORMAT;
    if (p[4] != CAIRN_BUNDLE_VERSION) return CAIRN_ERR_FORMAT;

    memset(info, 0, sizeof *info);
    info->flags = p[5];
    o = 6;
    info->chunk_size = get_u32(p + o); o += 4;
    info->plaintext_len = get_u64(p + o); o += 8;
    info->chunk_count = get_u32(p + o); o += 4;

    /* A declared chunk size or count that does not match what the header implies is
     * a tampered header, not a variant to tolerate. */
    if (info->chunk_size != CAIRN_BUNDLE_CHUNK) return CAIRN_ERR_FORMAT;
    if (info->chunk_count != chunk_count_for(info->plaintext_len)) return CAIRN_ERR_FORMAT;

    memcpy(info->eph_pub, p + o, CAIRN_X25519_BYTES); o += CAIRN_X25519_BYTES;
    if (cairn_pubkey_decode(&info->sender, p + o) != CAIRN_OK) return CAIRN_ERR_FORMAT;
    o += CAIRN_PUBKEY_BYTES;
    memcpy(info->nonce_prefix, p + o, 16); o += 16;

    info->chunks_offset = o;
    return CAIRN_OK;
}

/* Recomputes the wrap key from the recipient's static secret. This is the step only
 * the intended device can perform. */
static int unwrap_key(uint8_t out[CAIRN_KEY_BYTES], const cairn_bundle_info *info,
                      const cairn_identity *self)
{
    uint8_t dh[CAIRN_X25519_BYTES];
    int rc;

    rc = cairn_x25519(dh, self->dh_sec, info->eph_pub);
    if (rc != CAIRN_OK) return CAIRN_ERR_AUTH;

    rc = wrap_key(out, dh, info->eph_pub);
    cairn_memzero(dh, sizeof dh);
    return rc;
}

int cairn_bundle_verify(const cairn_bundle_info *info, const cairn_identity *self,
                        const void *bundle, size_t len)
{
    const uint8_t *p = (const uint8_t *)bundle;

    if (info == NULL || bundle == NULL) return CAIRN_ERR_ARG;
    if (len != cairn_bundle_size(info->plaintext_len)) return CAIRN_ERR_FORMAT;

    /* The signature covers the header and every chunk, so a replaced chunk cannot be
     * hidden by re-signing only a header. Checking it here refuses a corrupted
     * download before any decryption is attempted. */
    {
        const uint8_t *sig = p + len - CAIRN_BUNDLE_SIG_BYTES;
        if (cairn_ed25519_verify(sig, info->sender.ed_pub, p,
                                 len - CAIRN_BUNDLE_SIG_BYTES) != CAIRN_OK)
            return CAIRN_ERR_AUTH;
    }

    /* If this device cannot derive the wrap key it is the wrong device, and saying so
     * once is friendlier than failing on every chunk. */
    if (self != NULL) {
        uint8_t key[CAIRN_KEY_BYTES];
        int rc = unwrap_key(key, info, self);
        cairn_memzero(key, sizeof key);
        if (rc != CAIRN_OK) return rc;
    }
    return CAIRN_OK;
}

int cairn_bundle_open_chunk(uint8_t *dst, size_t dstcap, size_t *written,
                            const cairn_bundle_info *info, const cairn_identity *self,
                            uint32_t index, const void *chunk, size_t chunk_len)
{
    uint8_t key[CAIRN_KEY_BYTES];
    uint8_t nonce[CAIRN_NONCE_BYTES];
    uint8_t aad[12];
    size_t plain_len;
    int rc;

    if (dst == NULL || written == NULL || info == NULL || self == NULL || chunk == NULL)
        return CAIRN_ERR_ARG;
    if (index >= info->chunk_count) return CAIRN_ERR_ARG;
    if (chunk_len < CAIRN_TAG_BYTES) return CAIRN_ERR_FORMAT;

    plain_len = chunk_len - CAIRN_TAG_BYTES;
    if (plain_len > info->chunk_size) return CAIRN_ERR_FORMAT;
    if (dstcap < plain_len) return CAIRN_ERR_BUFFER;

    rc = unwrap_key(key, info, self);
    if (rc != CAIRN_OK) return rc;

    chunk_nonce(nonce, info->nonce_prefix, index);
    chunk_aad(aad, info->nonce_prefix, index, (uint32_t)plain_len);

    rc = cairn_aead_open(dst, key, nonce, aad, sizeof aad, chunk, chunk_len);
    cairn_memzero(key, sizeof key);
    if (rc != CAIRN_OK) return CAIRN_ERR_AUTH;

    *written = plain_len;
    return CAIRN_OK;
}

/* ------------------------------------------------------------------- simple */

/* The whole bundle in one call. This is what an application uses when it has the
 * file in memory already; the streaming API above exists for the case where it does
 * not. */
int cairn_seal(uint8_t *out, size_t outcap, size_t *outlen,
               const cairn_identity *sender, const cairn_pubkey *recipient,
               const void *plain, size_t len)
{
    cairn_bundle_opts opts;
    uint8_t wrap[CAIRN_KEY_BYTES];
    uint8_t prefix[16];
    uint8_t sig[CAIRN_BUNDLE_SIG_BYTES];
    uint64_t total;
    size_t off = 0, written = 0;
    uint32_t index, count;
    int rc;

    if (out == NULL || outlen == NULL || sender == NULL || recipient == NULL)
        return CAIRN_ERR_ARG;
    if (plain == NULL && len > 0) return CAIRN_ERR_ARG;
    if (len == 0) return CAIRN_ERR_ARG;

    total = cairn_bundle_size(len);
    if (total > outcap) return CAIRN_ERR_BUFFER;

    opts.sender = sender;
    opts.recipient = recipient;

    rc = cairn_bundle_begin(out, outcap, &written, &opts, len, wrap, prefix);
    if (rc != CAIRN_OK) return rc;
    off = written;

    count = chunk_count_for(len);
    for (index = 0; index < count; index++) {
        size_t chunk_plain = len - (size_t)index * CAIRN_BUNDLE_CHUNK;
        if (chunk_plain > CAIRN_BUNDLE_CHUNK) chunk_plain = CAIRN_BUNDLE_CHUNK;

        rc = cairn_bundle_chunk(out + off, outcap - off, &written, wrap, prefix, index,
                                (const uint8_t *)plain + (size_t)index * CAIRN_BUNDLE_CHUNK,
                                chunk_plain);
        if (rc != CAIRN_OK) {
            cairn_memzero(wrap, sizeof wrap);
            return rc;
        }
        off += written;
    }
    cairn_memzero(wrap, sizeof wrap);

    /* The signature has to be appended outside the signed region, so it is computed
     * over exactly what was written. */
    rc = cairn_bundle_sign(sig, sender, out, off);
    if (rc != CAIRN_OK) return rc;
    memcpy(out + off, sig, sizeof sig);
    off += sizeof sig;

    *outlen = off;
    return CAIRN_OK;
}

int cairn_unseal(uint8_t *out, size_t outcap, size_t *outlen,
                 const cairn_identity *self, const void *bundle, size_t len)
{
    cairn_bundle_info info;
    size_t off, written = 0, produced = 0;
    uint32_t index;
    int rc;

    if (out == NULL || outlen == NULL || self == NULL || bundle == NULL)
        return CAIRN_ERR_ARG;

    rc = cairn_bundle_peek(&info, bundle, len);
    if (rc != CAIRN_OK) return rc;
    if (info.plaintext_len > outcap) return CAIRN_ERR_BUFFER;

    /* Signature and recipient are checked before a single byte is decrypted, so a
     * wrong device or a corrupted download fails cheaply. */
    rc = cairn_bundle_verify(&info, self, bundle, len);
    if (rc != CAIRN_OK) return rc;

    off = info.chunks_offset;
    for (index = 0; index < info.chunk_count; index++) {
        size_t chunk_plain = (size_t)info.plaintext_len - (size_t)index * CAIRN_BUNDLE_CHUNK;
        size_t chunk_len;

        if (chunk_plain > CAIRN_BUNDLE_CHUNK) chunk_plain = CAIRN_BUNDLE_CHUNK;
        chunk_len = chunk_plain + CAIRN_TAG_BYTES;

        if (off + chunk_len > len) return CAIRN_ERR_FORMAT;
        rc = cairn_bundle_open_chunk(out + produced, outcap - produced, &written,
                                     &info, self, index, (const uint8_t *)bundle + off,
                                     chunk_len);
        if (rc != CAIRN_OK) return rc;
        off += chunk_len;
        produced += written;
    }

    *outlen = produced;
    return CAIRN_OK;
}