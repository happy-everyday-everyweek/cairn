/* cairn: layered wrapping derived from a passphrase.
 *
 * Design note: this is obfuscation, not confidentiality. Each layer is an
 * independent XChaCha20-Poly1305 wrap with a per-message random nonce prefix,
 * so the wire bytes look uniformly random and the plaintext length is bucketed.
 * The outermost AEAD is what actually protects the content; the inner layers
 * only deny an observer the satisfaction of recognising structure.
 */
#include "cairn/nested.h"

#include <string.h>

#define SALT_BYTES 16
#define NONCE_PREFIX_BYTES 16
#define LENGTH_FIELD_BYTES 4
#define LAYER_TAG_BYTES CAIRN_TAG_BYTES

static size_t pad_to_block(size_t n)
{
    /* Always round up to the next block, even when n is already a multiple of
     * the block size. A full extra block hides the exact boundary, at the cost
     * of at most CAIRN_NESTED_BLOCK bytes. */
    return ((n / CAIRN_NESTED_BLOCK) + 1) * CAIRN_NESTED_BLOCK;
}

size_t cairn_nested_sealed_size(size_t plaintextlen)
{
    return NONCE_PREFIX_BYTES + LENGTH_FIELD_BYTES + pad_to_block(plaintextlen) +
           (size_t)CAIRN_NESTED_LAYERS * LAYER_TAG_BYTES;
}

int cairn_nested_from_password(cairn_nested *n,
                               const void *password, size_t passwordlen,
                               const uint8_t salt[16])
{
    static const uint8_t no_salt[16] = {0};
    const uint8_t *use_salt;
    int rc;

    if (n == NULL) return CAIRN_ERR_ARG;
    if (password == NULL && passwordlen > 0) return CAIRN_ERR_ARG;

    use_salt = salt != NULL ? salt : no_salt;
    memset(n, 0, sizeof *n);
    memcpy(n->salt, use_salt, sizeof n->salt);

    /* Stretching the passphrase is the only thing standing between a short
     * shared secret and an offline guess, so do it before deriving the key. */
    rc = cairn_kdf_slow(n->key, password, passwordlen,
                        use_salt, sizeof n->salt, 4096);
    if (rc != CAIRN_OK) {
        cairn_memzero(n, sizeof *n);
        return rc;
    }
    return CAIRN_OK;
}

void cairn_nested_clear(cairn_nested *n)
{
    if (n != NULL) cairn_memzero(n, sizeof *n);
}

/* Builds the nonce for a given layer from the message prefix and the index. */
static void layer_nonce(uint8_t nonce[CAIRN_NONCE_BYTES],
                        const uint8_t prefix[NONCE_PREFIX_BYTES],
                        uint8_t index)
{
    memset(nonce, 0, CAIRN_NONCE_BYTES);
    memcpy(nonce, prefix, NONCE_PREFIX_BYTES);
    nonce[NONCE_PREFIX_BYTES] = index;
}

/* Layer keys are independent per index, so a break in one layer says nothing
 * about the next. */
static void layer_key(uint8_t out[CAIRN_KEY_BYTES],
                      const uint8_t master[CAIRN_KEY_BYTES],
                      uint8_t index)
{
    char info[8];
    info[0] = 'l';
    info[1] = 'a';
    info[2] = 'y';
    info[3] = 'e';
    info[4] = 'r';
    info[5] = (char)index;
    cairn_kdf(out, CAIRN_KEY_BYTES, master, info, 6);
}

int cairn_nested_seal(const cairn_nested *n,
                      uint8_t *out, size_t outcap, size_t *outlen,
                      const void *plaintext, size_t plaintextlen)
{
    uint8_t prefix[NONCE_PREFIX_BYTES];
    uint8_t *cur;
    size_t need, padded, i;
    uint8_t layer;

    if (n == NULL || out == NULL || outlen == NULL) return CAIRN_ERR_ARG;
    if (plaintext == NULL && plaintextlen > 0) return CAIRN_ERR_ARG;

    need = cairn_nested_sealed_size(plaintextlen);
    if (outcap < need) return CAIRN_ERR_BUFFER;

    if (cairn_random_bytes(prefix, sizeof prefix) != CAIRN_OK) return CAIRN_ERR_IO;

    /* Padded plaintext plus its length field, assembled after the prefix. */
    padded = pad_to_block(plaintextlen);
    cur = out + NONCE_PREFIX_BYTES;

    cur[0] = (uint8_t)(plaintextlen);
    cur[1] = (uint8_t)(plaintextlen >> 8);
    cur[2] = (uint8_t)(plaintextlen >> 16);
    cur[3] = (uint8_t)(plaintextlen >> 24);
    if (plaintextlen > 0) memcpy(cur + LENGTH_FIELD_BYTES, plaintext, plaintextlen);
    for (i = plaintextlen; i < padded; i++) cur[LENGTH_FIELD_BYTES + i] = 0;

    {
        size_t body = LENGTH_FIELD_BYTES + padded;
        /* Each layer adds a tag, so the buffer grows. Work in place from the
         * end backwards: the plaintext region is already in position. */
        for (layer = 0; layer < CAIRN_NESTED_LAYERS; layer++) {
            uint8_t key[CAIRN_KEY_BYTES];
            uint8_t nonce[CAIRN_NONCE_BYTES];
            layer_key(key, n->key, layer);
            layer_nonce(nonce, prefix, layer);
            cairn_aead_seal(cur, key, nonce, prefix, sizeof prefix, cur, body);
            cairn_memzero(key, sizeof key);
            body += LAYER_TAG_BYTES;
        }
    }

    memcpy(out, prefix, sizeof prefix);
    *outlen = need;
    return CAIRN_OK;
}

int cairn_nested_open(const cairn_nested *n,
                      uint8_t *out, size_t outcap, size_t *outlen,
                      const void *ciphertext, size_t ciphertextlen)
{
    const uint8_t *in = (const uint8_t *)ciphertext;
    uint8_t prefix[NONCE_PREFIX_BYTES];
    uint8_t *cur;
    size_t body, padded, i;
    int layer;
    size_t declared;

    if (n == NULL || out == NULL || outlen == NULL || ciphertext == NULL)
        return CAIRN_ERR_ARG;
    if (ciphertextlen < cairn_nested_sealed_size(0)) return CAIRN_ERR_FORMAT;

    memcpy(prefix, in, sizeof prefix);
    body = ciphertextlen - NONCE_PREFIX_BYTES;
    if (outcap < body) return CAIRN_ERR_BUFFER;

    memcpy(out, in + NONCE_PREFIX_BYTES, body);
    cur = out;

    for (layer = CAIRN_NESTED_LAYERS - 1; layer >= 0; layer--) {
        uint8_t key[CAIRN_KEY_BYTES];
        uint8_t nonce[CAIRN_NONCE_BYTES];
        int rc;

        if (body < LAYER_TAG_BYTES) return CAIRN_ERR_FORMAT;
        layer_key(key, n->key, (uint8_t)layer);
        layer_nonce(nonce, prefix, (uint8_t)layer);
        rc = cairn_aead_open(cur, key, nonce, prefix, sizeof prefix, cur, body);
        cairn_memzero(key, sizeof key);
        if (rc != CAIRN_OK) return CAIRN_ERR_AUTH;
        body -= LAYER_TAG_BYTES;
    }

    if (body < LENGTH_FIELD_BYTES) return CAIRN_ERR_FORMAT;
    declared = (size_t)cur[0] | ((size_t)cur[1] << 8) |
               ((size_t)cur[2] << 16) | ((size_t)cur[3] << 24);
    padded = body - LENGTH_FIELD_BYTES;
    if (declared > padded) return CAIRN_ERR_FORMAT;

    if (declared > 0) memmove(out, cur + LENGTH_FIELD_BYTES, declared);
    /* Padding bytes are cleared so no stale plaintext tails survive. */
    for (i = declared; i < padded; i++) out[i] = 0;
    *outlen = declared;
    return CAIRN_OK;
}