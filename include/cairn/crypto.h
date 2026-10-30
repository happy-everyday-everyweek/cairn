/* cairn: cryptographic primitives.
 *
 * The maths is vendored, not handwritten: Monocypher provides X25519, Ed25519,
 * ChaCha20-Poly1305 and BLAKE2b; PQClean provides ML-KEM-768. See vendor/.
 */
#ifndef CAIRN_CRYPTO_H
#define CAIRN_CRYPTO_H

#include <stddef.h>
#include <stdint.h>

#include "cairn/cairn.h"

#ifdef __cplusplus
extern "C" {
#endif

#define CAIRN_HASH_BYTES 64
#define CAIRN_KEY_BYTES 32
#define CAIRN_NONCE_BYTES 24
#define CAIRN_TAG_BYTES 16

#define CAIRN_X25519_BYTES 32
#define CAIRN_ED25519_PUB_BYTES 32
#define CAIRN_ED25519_SEC_BYTES 64
#define CAIRN_ED25519_SIG_BYTES 64

#define CAIRN_MLKEM_PUB_BYTES 1184
#define CAIRN_MLKEM_SEC_BYTES 2400
#define CAIRN_MLKEM_CT_BYTES 1088
#define CAIRN_MLKEM_SS_BYTES 32

/* Streaming BLAKE2b, sized to match the vendored context. */
typedef struct {
    uint64_t opaque[32];
    size_t outlen;
} cairn_blake2b_state;

int cairn_hash(uint8_t *out, size_t outlen, const void *data, size_t len);
int cairn_blake2b_init(cairn_blake2b_state *st, size_t outlen,
                       const void *key, size_t keylen);
int cairn_blake2b_update(cairn_blake2b_state *st, const void *data, size_t len);
int cairn_blake2b_final(cairn_blake2b_state *st, uint8_t *out, size_t outlen);

int cairn_mac(uint8_t *out, size_t outlen,
              const void *key, size_t keylen,
              const void *data, size_t len);

int cairn_kdf(uint8_t *out, size_t outlen,
              const uint8_t key[CAIRN_KEY_BYTES],
              const void *info, size_t infolen);

int cairn_kdf_slow(uint8_t out[CAIRN_KEY_BYTES],
                   const void *password, size_t passwordlen,
                   const void *salt, size_t saltlen,
                   uint32_t iterations);

int cairn_aead_seal(uint8_t *ciphertext,
                    const uint8_t key[CAIRN_KEY_BYTES],
                    const uint8_t nonce[CAIRN_NONCE_BYTES],
                    const void *aad, size_t aadlen,
                    const void *plaintext, size_t plaintextlen);

int cairn_aead_open(uint8_t *plaintext,
                    const uint8_t key[CAIRN_KEY_BYTES],
                    const uint8_t nonce[CAIRN_NONCE_BYTES],
                    const void *aad, size_t aadlen,
                    const void *ciphertext, size_t ciphertextlen);

int cairn_x25519_keypair(uint8_t pub[CAIRN_X25519_BYTES],
                         uint8_t sec[CAIRN_X25519_BYTES]);
int cairn_x25519(uint8_t shared[CAIRN_X25519_BYTES],
                 const uint8_t sec[CAIRN_X25519_BYTES],
                 const uint8_t pub[CAIRN_X25519_BYTES]);

int cairn_ed25519_keypair(uint8_t pub[CAIRN_ED25519_PUB_BYTES],
                          uint8_t sec[CAIRN_ED25519_SEC_BYTES]);
int cairn_ed25519_keypair_from_seed(uint8_t pub[CAIRN_ED25519_PUB_BYTES],
                                     uint8_t sec[CAIRN_ED25519_SEC_BYTES],
                                     uint8_t seed[32]);
int cairn_ed25519_sign(uint8_t sig[CAIRN_ED25519_SIG_BYTES],
                       const uint8_t sec[CAIRN_ED25519_SEC_BYTES],
                       const void *msg, size_t msglen);
int cairn_ed25519_verify(const uint8_t sig[CAIRN_ED25519_SIG_BYTES],
                         const uint8_t pub[CAIRN_ED25519_PUB_BYTES],
                         const void *msg, size_t msglen);

int cairn_mlkem768_keypair(uint8_t pub[CAIRN_MLKEM_PUB_BYTES],
                           uint8_t sec[CAIRN_MLKEM_SEC_BYTES]);
int cairn_mlkem768_encaps(uint8_t ct[CAIRN_MLKEM_CT_BYTES],
                          uint8_t ss[CAIRN_MLKEM_SS_BYTES],
                          const uint8_t pub[CAIRN_MLKEM_PUB_BYTES]);
int cairn_mlkem768_decaps(uint8_t ss[CAIRN_MLKEM_SS_BYTES],
                          const uint8_t ct[CAIRN_MLKEM_CT_BYTES],
                          const uint8_t sec[CAIRN_MLKEM_SEC_BYTES]);

int cairn_random_bytes(void *buf, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* CAIRN_CRYPTO_H */
