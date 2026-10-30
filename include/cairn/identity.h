/* cairn: long term identity and the six digit safety code.
 *
 * An identity holds three key pairs: Ed25519 for signatures, X25519 for the
 * key agreement, and ML-KEM-768 for the post quantum part. They are generated
 * together and published together, which lets the fingerprint cover all three
 * at once.
 */
#ifndef CAIRN_IDENTITY_H
#define CAIRN_IDENTITY_H

#include <stddef.h>
#include <stdint.h>

#include "cairn/cairn.h"
#include "cairn/crypto.h"

#ifdef __cplusplus
extern "C" {
#endif

#define CAIRN_ID_BYTES 16
#define CAIRN_FP_BYTES 32
#define CAIRN_SAFETY_CODE_DIGITS 6
#define CAIRN_SAFETY_CODE_BYTES (CAIRN_SAFETY_CODE_DIGITS + 1)

typedef struct {
    uint8_t id[CAIRN_ID_BYTES];
    uint8_t ed_pub[CAIRN_ED25519_PUB_BYTES];
    uint8_t ed_sec[CAIRN_ED25519_SEC_BYTES];
    uint8_t dh_pub[CAIRN_X25519_BYTES];
    uint8_t dh_sec[CAIRN_X25519_BYTES];
    uint8_t kem_pub[CAIRN_MLKEM_PUB_BYTES];
    uint8_t kem_sec[CAIRN_MLKEM_SEC_BYTES];
} cairn_identity;

/* The public half, which is what a peer receives before any handshake. */
typedef struct {
    uint8_t id[CAIRN_ID_BYTES];
    uint8_t ed_pub[CAIRN_ED25519_PUB_BYTES];
    uint8_t dh_pub[CAIRN_X25519_BYTES];
    uint8_t kem_pub[CAIRN_MLKEM_PUB_BYTES];
} cairn_pubkey;

/* Total size of the serialised public key as written by cairn_pubkey_encode. */
#define CAIRN_PUBKEY_BYTES (CAIRN_ID_BYTES + 32 + 32 + CAIRN_MLKEM_PUB_BYTES)

int cairn_identity_generate(cairn_identity *id);
int cairn_identity_pubkey(const cairn_identity *id, cairn_pubkey *out);
void cairn_identity_clear(cairn_identity *id);

/* 32 byte fingerprint over the public halves. Stable across calls and across
 * processes, so it can be printed or compared by hand. */
int cairn_pubkey_fingerprint(uint8_t out[CAIRN_FP_BYTES], const cairn_pubkey *pk);
int cairn_identity_fingerprint(uint8_t out[CAIRN_FP_BYTES], const cairn_identity *id);

/* Six decimal digits derived from both fingerprints. Sorting the two before
 * hashing means two peers compute the same code without agreeing on an order.
 * out receives exactly six digits plus a terminator. */
int cairn_safety_code(char out[CAIRN_SAFETY_CODE_BYTES],
                      const uint8_t fp_a[CAIRN_FP_BYTES],
                      const uint8_t fp_b[CAIRN_FP_BYTES]);

/* Short human readable form of a fingerprint, six groups of two hex digits.
 * out must hold 18 bytes. */
int cairn_fingerprint_text(char out[18], const uint8_t fp[CAIRN_FP_BYTES]);

int cairn_pubkey_encode(uint8_t out[CAIRN_PUBKEY_BYTES], const cairn_pubkey *pk);
int cairn_pubkey_decode(cairn_pubkey *pk, const uint8_t in[CAIRN_PUBKEY_BYTES]);

#ifdef __cplusplus
}
#endif

#endif /* CAIRN_IDENTITY_H */
