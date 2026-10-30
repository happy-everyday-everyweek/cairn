/* cairn: layered wrapping, derived from a shared passphrase.
 *
 * This is a traffic obfuscation layer, not a confidentiality mechanism. Every
 * layer after the first is wrapped with an independent key so the wire format
 * does not reveal the plaintext structure, but the secrecy of the whole chain
 * rests on the outermost AEAD. Nested wrapping cannot make a weak passphrase
 * strong; use cairn_nested_from_password which stretches it.
 *
 * Wire layout of a sealed blob:
 *
 *   salt[16] || salt-free layers... 
 *
 * Concretely: nonce_prefix[16] || layer( layer( layer( padded(plaintext) ) ) )
 */
#ifndef CAIRN_NESTED_H
#define CAIRN_NESTED_H

#include <stddef.h>
#include <stdint.h>

#include "cairn/cairn.h"
#include "cairn/crypto.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Number of AEAD layers applied to each blob. */
#define CAIRN_NESTED_LAYERS 3

/* Plaintexts are padded up to a multiple of this before wrapping, so the
 * ciphertext length only leaks a coarse size bucket. */
#define CAIRN_NESTED_BLOCK 64

/* Per message overhead: nonce prefix, one tag per layer, padding length field. */
#define CAIRN_NESTED_OVERHEAD \
    (16 + 4 + CAIRN_NESTED_LAYERS * CAIRN_TAG_BYTES + CAIRN_NESTED_BLOCK)

/* Bytes needed to seal a plaintext of n bytes. */
size_t cairn_nested_sealed_size(size_t plaintextlen);

typedef struct {
    uint8_t key[CAIRN_KEY_BYTES];
    uint8_t salt[16];
} cairn_nested;

/* Derives the session keys from a passphrase. Both sides that use the same
 * passphrase and salt arrive at the same keys. Salt must be exchanged out of
 * band or carried in the handshake; passing NULL means an all zero salt. */
int cairn_nested_from_password(cairn_nested *n,
                               const void *password, size_t passwordlen,
                               const uint8_t salt[16]);

/* Wraps plaintext into out. out must hold cairn_nested_sealed_size(plaintextlen)
 * bytes. outlen receives the exact number written. */
int cairn_nested_seal(const cairn_nested *n,
                      uint8_t *out, size_t outcap, size_t *outlen,
                      const void *plaintext, size_t plaintextlen);

/* Unwraps a blob produced by cairn_nested_seal. out must hold at least
 * ciphertextlen bytes; outlen receives the recovered length. Returns
 * CAIRN_ERR_AUTH when any layer fails to authenticate. */
int cairn_nested_open(const cairn_nested *n,
                      uint8_t *out, size_t outcap, size_t *outlen,
                      const void *ciphertext, size_t ciphertextlen);

/* Wipes keys held by the session. */
void cairn_nested_clear(cairn_nested *n);

#ifdef __cplusplus
}
#endif

#endif /* CAIRN_NESTED_H */
