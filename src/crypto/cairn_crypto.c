/* cairn: cryptographic primitives, wrapping vendored implementations.
 *
 * The maths is not handwritten here on purpose. X25519, Ed25519, XChaCha20-
 * Poly1305 and BLAKE2b come from Monocypher; ML-KEM-768 comes from PQClean.
 * Both are vendored under vendor/. This file only adapts their interfaces and
 * adds the composition the protocol needs.
 */
#include "cairn/crypto.h"

#include <string.h>

#include "monocypher.h"
#include "monocypher-ed25519.h"
#include "fips202.h"
#include "kem.h"

/* The vendored context is larger than what we expose; embed it directly. */
typedef struct {
    crypto_blake2b_ctx ctx;
    size_t outlen;
} blake_state;

/* ---------------------------------------------------------------- hashing */

int cairn_hash(uint8_t *out, size_t outlen, const void *data, size_t len)
{
    if (out == NULL || outlen == 0 || outlen > 64) return CAIRN_ERR_ARG;
    if (data == NULL && len > 0) return CAIRN_ERR_ARG;
    crypto_blake2b(out, outlen, (const uint8_t *)data, len);
    return CAIRN_OK;
}

int cairn_blake2b_init(cairn_blake2b_state *st, size_t outlen,
                       const void *key, size_t keylen)
{
    blake_state *s = (blake_state *)st;
    if (st == NULL || outlen == 0 || outlen > 64) return CAIRN_ERR_ARG;
    if (keylen > 64) return CAIRN_ERR_ARG;
    if (keylen > 0 && key == NULL) return CAIRN_ERR_ARG;
    memset(st, 0, sizeof *st);
    if (keylen > 0)
        crypto_blake2b_keyed_init(&s->ctx, outlen, (const uint8_t *)key, keylen);
    else
        crypto_blake2b_init(&s->ctx, outlen);
    s->outlen = outlen;
    return CAIRN_OK;
}

int cairn_blake2b_update(cairn_blake2b_state *st, const void *data, size_t len)
{
    blake_state *s = (blake_state *)st;
    if (st == NULL || (data == NULL && len > 0)) return CAIRN_ERR_ARG;
    crypto_blake2b_update(&s->ctx, (const uint8_t *)data, len);
    return CAIRN_OK;
}

int cairn_blake2b_final(cairn_blake2b_state *st, uint8_t *out, size_t outlen)
{
    blake_state *s = (blake_state *)st;
    if (st == NULL || out == NULL) return CAIRN_ERR_ARG;
    if (outlen != s->outlen) return CAIRN_ERR_ARG;
    crypto_blake2b_final(&s->ctx, out);
    cairn_memzero(st, sizeof *st);
    return CAIRN_OK;
}

int cairn_mac(uint8_t *out, size_t outlen,
              const void *key, size_t keylen,
              const void *data, size_t len)
{
    if (out == NULL || key == NULL || keylen == 0 || keylen > 64) return CAIRN_ERR_ARG;
    if (data == NULL && len > 0) return CAIRN_ERR_ARG;
    crypto_blake2b_keyed(out, outlen, (const uint8_t *)key, keylen,
                         (const uint8_t *)data, len);
    return CAIRN_OK;
}

/* Counter mode keyed hash. Distinct labels give independent outputs. */
int cairn_kdf(uint8_t *out, size_t outlen,
              const uint8_t key[CAIRN_KEY_BYTES],
              const void *info, size_t infolen)
{
    static const char prefix[] = "cairn-kdf-v1";
    crypto_blake2b_ctx ctx;
    uint8_t counter[4];
    size_t done = 0;
    uint32_t block = 0;

    if (out == NULL || key == NULL || outlen == 0) return CAIRN_ERR_ARG;
    if (info == NULL && infolen > 0) return CAIRN_ERR_ARG;

    while (done < outlen) {
        uint8_t digest[64];
        size_t take = outlen - done < 64 ? outlen - done : 64;

        counter[0] = (uint8_t)(block);
        counter[1] = (uint8_t)(block >> 8);
        counter[2] = (uint8_t)(block >> 16);
        counter[3] = (uint8_t)(block >> 24);

        crypto_blake2b_keyed_init(&ctx, 64, key, CAIRN_KEY_BYTES);
        crypto_blake2b_update(&ctx, (const uint8_t *)prefix, sizeof prefix - 1);
        crypto_blake2b_update(&ctx, counter, sizeof counter);
        crypto_blake2b_update(&ctx, (const uint8_t *)info, infolen);
        crypto_blake2b_final(&ctx, digest);

        memcpy(out + done, digest, take);
        cairn_memzero(digest, sizeof digest);
        done += take;
        block++;
    }
    return CAIRN_OK;
}

int cairn_kdf_slow(uint8_t out[CAIRN_KEY_BYTES],
                   const void *password, size_t passwordlen,
                   const void *salt, size_t saltlen,
                   uint32_t iterations)
{
    uint8_t block[CAIRN_KEY_BYTES];
    uint32_t i;

    if (out == NULL || password == NULL || salt == NULL) return CAIRN_ERR_ARG;
    if (iterations == 0) return CAIRN_ERR_ARG;

    crypto_blake2b_keyed(block, sizeof block, (const uint8_t *)password, passwordlen,
                         (const uint8_t *)salt, saltlen);
    for (i = 1; i < iterations; i++) {
        uint8_t next[CAIRN_KEY_BYTES];
        crypto_blake2b_keyed(next, sizeof next, block, sizeof block, block, sizeof block);
        memcpy(block, next, sizeof block);
        cairn_memzero(next, sizeof next);
    }
    memcpy(out, block, sizeof block);
    cairn_memzero(block, sizeof block);
    return CAIRN_OK;
}

/* ------------------------------------------------------------------- AEAD */

int cairn_aead_seal(uint8_t *ciphertext,
                    const uint8_t key[CAIRN_KEY_BYTES],
                    const uint8_t nonce[CAIRN_NONCE_BYTES],
                    const void *aad, size_t aadlen,
                    const void *plaintext, size_t plaintextlen)
{
    if (ciphertext == NULL || key == NULL || nonce == NULL) return CAIRN_ERR_ARG;
    if (aad == NULL && aadlen > 0) return CAIRN_ERR_ARG;
    if (plaintext == NULL && plaintextlen > 0) return CAIRN_ERR_ARG;

    crypto_aead_lock(ciphertext, ciphertext + plaintextlen, key, nonce,
                     (const uint8_t *)aad, aadlen,
                     (const uint8_t *)plaintext, plaintextlen);
    return CAIRN_OK;
}

int cairn_aead_open(uint8_t *plaintext,
                    const uint8_t key[CAIRN_KEY_BYTES],
                    const uint8_t nonce[CAIRN_NONCE_BYTES],
                    const void *aad, size_t aadlen,
                    const void *ciphertext, size_t ciphertextlen)
{
    if (plaintext == NULL || key == NULL || nonce == NULL) return CAIRN_ERR_ARG;
    if (ciphertext == NULL || ciphertextlen < CAIRN_TAG_BYTES) return CAIRN_ERR_FORMAT;
    if (aad == NULL && aadlen > 0) return CAIRN_ERR_ARG;

    if (crypto_aead_unlock(plaintext,
                           (const uint8_t *)ciphertext + ciphertextlen - CAIRN_TAG_BYTES,
                           key, nonce, (const uint8_t *)aad, aadlen,
                           (const uint8_t *)ciphertext,
                           ciphertextlen - CAIRN_TAG_BYTES) != 0)
        return CAIRN_ERR_AUTH;
    return CAIRN_OK;
}

/* ------------------------------------------------------------- key exchange */

int cairn_x25519_keypair(uint8_t pub[CAIRN_X25519_BYTES],
                         uint8_t sec[CAIRN_X25519_BYTES])
{
    int rc;
    if (pub == NULL || sec == NULL) return CAIRN_ERR_ARG;
    rc = cairn_random_bytes(sec, CAIRN_X25519_BYTES);
    if (rc != CAIRN_OK) return rc;
    crypto_x25519_public_key(pub, sec);
    return CAIRN_OK;
}

int cairn_x25519(uint8_t shared[CAIRN_X25519_BYTES],
                 const uint8_t sec[CAIRN_X25519_BYTES],
                 const uint8_t pub[CAIRN_X25519_BYTES])
{
    static const uint8_t zero[32] = {0};

    if (shared == NULL || sec == NULL || pub == NULL) return CAIRN_ERR_ARG;
    crypto_x25519(shared, sec, pub);
    if (cairn_memeq(shared, zero, 32)) return CAIRN_ERR_CRYPTO;
    return CAIRN_OK;
}

/* --------------------------------------------------------------- signatures */

int cairn_ed25519_keypair(uint8_t pub[CAIRN_ED25519_PUB_BYTES],
                          uint8_t sec[CAIRN_ED25519_SEC_BYTES])
{
    uint8_t seed[32];
    int rc;

    if (pub == NULL || sec == NULL) return CAIRN_ERR_ARG;
    rc = cairn_random_bytes(seed, sizeof seed);
    if (rc != CAIRN_OK) return rc;
    /* RFC 8032 Ed25519: 32 byte seed, public key derived with SHA-512. */
    crypto_ed25519_key_pair(sec, pub, seed);
    cairn_memzero(seed, sizeof seed);
    return CAIRN_OK;
}

int cairn_ed25519_keypair_from_seed(uint8_t pub[CAIRN_ED25519_PUB_BYTES],
                                     uint8_t sec[CAIRN_ED25519_SEC_BYTES],
                                     uint8_t seed[32])
{
    if (pub == NULL || sec == NULL || seed == NULL) return CAIRN_ERR_ARG;
    crypto_ed25519_key_pair(sec, pub, seed);
    return CAIRN_OK;
}

int cairn_ed25519_sign(uint8_t sig[CAIRN_ED25519_SIG_BYTES],
                       const uint8_t sec[CAIRN_ED25519_SEC_BYTES],
                       const void *msg, size_t msglen)
{
    if (sig == NULL || sec == NULL) return CAIRN_ERR_ARG;
    if (msg == NULL && msglen > 0) return CAIRN_ERR_ARG;
    crypto_ed25519_sign(sig, sec, (const uint8_t *)msg, msglen);
    return CAIRN_OK;
}

int cairn_ed25519_verify(const uint8_t sig[CAIRN_ED25519_SIG_BYTES],
                         const uint8_t pub[CAIRN_ED25519_PUB_BYTES],
                         const void *msg, size_t msglen)
{
    if (sig == NULL || pub == NULL) return CAIRN_ERR_ARG;
    if (msg == NULL && msglen > 0) return CAIRN_ERR_ARG;
    return crypto_ed25519_check(sig, pub, (const uint8_t *)msg, msglen) == 0
               ? CAIRN_OK : CAIRN_ERR_AUTH;
}

/* -------------------------------------------------------------------- KEM */

int cairn_mlkem768_keypair(uint8_t pub[CAIRN_MLKEM_PUB_BYTES],
                           uint8_t sec[CAIRN_MLKEM_SEC_BYTES])
{
    if (pub == NULL || sec == NULL) return CAIRN_ERR_ARG;
    PQCLEAN_MLKEM768_CLEAN_crypto_kem_keypair(pub, sec);
    return CAIRN_OK;
}

int cairn_mlkem768_encaps(uint8_t ct[CAIRN_MLKEM_CT_BYTES],
                          uint8_t ss[CAIRN_MLKEM_SS_BYTES],
                          const uint8_t pub[CAIRN_MLKEM_PUB_BYTES])
{
    if (ct == NULL || ss == NULL || pub == NULL) return CAIRN_ERR_ARG;
    PQCLEAN_MLKEM768_CLEAN_crypto_kem_enc(ct, ss, pub);
    return CAIRN_OK;
}

int cairn_mlkem768_decaps(uint8_t ss[CAIRN_MLKEM_SS_BYTES],
                          const uint8_t ct[CAIRN_MLKEM_CT_BYTES],
                          const uint8_t sec[CAIRN_MLKEM_SEC_BYTES])
{
    if (ss == NULL || ct == NULL || sec == NULL) return CAIRN_ERR_ARG;
    PQCLEAN_MLKEM768_CLEAN_crypto_kem_dec(ss, ct, sec);
    return CAIRN_OK;
}
