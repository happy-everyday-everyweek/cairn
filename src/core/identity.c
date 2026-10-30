/* cairn: identity, fingerprint and safety code. */
#include "cairn/identity.h"

#include <string.h>

static const char kFingerprintDomain[] = "cairn-fingerprint-v1";
static const char kCodeDomain[] = "cairn-safety-code-v1";

int cairn_identity_generate(cairn_identity *id)
{
    if (id == NULL) return CAIRN_ERR_ARG;

    memset(id, 0, sizeof *id);
    if (cairn_ed25519_keypair(id->ed_pub, id->ed_sec) != CAIRN_OK) goto fail;
    if (cairn_x25519_keypair(id->dh_pub, id->dh_sec) != CAIRN_OK) goto fail;
    if (cairn_mlkem768_keypair(id->kem_pub, id->kem_sec) != CAIRN_OK) goto fail;

    /* The local id is a short handle for logs and neighbour tables. It is not
     * a security boundary; the fingerprint is. Deriving it from the public
     * keys keeps it stable for a given identity without extra bookkeeping. */
    if (cairn_hash(id->id, sizeof id->id, id->ed_pub, CAIRN_ED25519_PUB_BYTES) != CAIRN_OK)
        goto fail;

    return CAIRN_OK;

fail:
    cairn_memzero(id, sizeof *id);
    return CAIRN_ERR_CRYPTO;
}

int cairn_identity_pubkey(const cairn_identity *id, cairn_pubkey *out)
{
    if (id == NULL || out == NULL) return CAIRN_ERR_ARG;
    memcpy(out->id, id->id, CAIRN_ID_BYTES);
    memcpy(out->ed_pub, id->ed_pub, CAIRN_ED25519_PUB_BYTES);
    memcpy(out->dh_pub, id->dh_pub, CAIRN_X25519_BYTES);
    memcpy(out->kem_pub, id->kem_pub, CAIRN_MLKEM_PUB_BYTES);
    return CAIRN_OK;
}

void cairn_identity_clear(cairn_identity *id)
{
    if (id != NULL) cairn_memzero(id, sizeof *id);
}

/* Fingerprints must be identical no matter which struct the caller holds, so
 * they are computed from the canonical serialised form. */
int cairn_pubkey_fingerprint(uint8_t out[CAIRN_FP_BYTES], const cairn_pubkey *pk)
{
    cairn_blake2b_state st;
    uint8_t wire[CAIRN_PUBKEY_BYTES];
    int rc;

    if (out == NULL || pk == NULL) return CAIRN_ERR_ARG;
    rc = cairn_pubkey_encode(wire, pk);
    if (rc != CAIRN_OK) return rc;

    rc = cairn_blake2b_init(&st, CAIRN_FP_BYTES, kFingerprintDomain,
                            sizeof kFingerprintDomain - 1);
    if (rc != CAIRN_OK) return rc;
    cairn_blake2b_update(&st, wire, sizeof wire);
    rc = cairn_blake2b_final(&st, out, CAIRN_FP_BYTES);
    cairn_memzero(wire, sizeof wire);
    return rc;
}

int cairn_identity_fingerprint(uint8_t out[CAIRN_FP_BYTES], const cairn_identity *id)
{
    cairn_pubkey pk;
    cairn_pubkey *volatile guard = &pk;

    if (out == NULL || id == NULL) return CAIRN_ERR_ARG;
    cairn_identity_pubkey(id, guard);
    return cairn_pubkey_fingerprint(out, guard);
}

/* Six digits from the two fingerprints, lower sorted first so both sides
 * compute the same value without a role negotiation. */
int cairn_safety_code(char out[CAIRN_SAFETY_CODE_BYTES],
                      const uint8_t fp_a[CAIRN_FP_BYTES],
                      const uint8_t fp_b[CAIRN_FP_BYTES])
{
    uint8_t digest[64];
    const uint8_t *first, *second;
    cairn_blake2b_state st;
    uint32_t value;
    int i, rc;

    if (out == NULL || fp_a == NULL || fp_b == NULL) return CAIRN_ERR_ARG;

    if (memcmp(fp_a, fp_b, CAIRN_FP_BYTES) <= 0) {
        first = fp_a;
        second = fp_b;
    } else {
        first = fp_b;
        second = fp_a;
    }

    rc = cairn_blake2b_init(&st, sizeof digest, kCodeDomain, sizeof kCodeDomain - 1);
    if (rc != CAIRN_OK) return rc;
    cairn_blake2b_update(&st, first, CAIRN_FP_BYTES);
    cairn_blake2b_update(&st, second, CAIRN_FP_BYTES);
    rc = cairn_blake2b_final(&st, digest, sizeof digest);
    if (rc != CAIRN_OK) return rc;

    /* 1000000 does not divide 2^32, so fold with a modulo and accept the
     * negligible bias; six digits are a human check, not a key. */
    value = ((uint32_t)digest[0]) | ((uint32_t)digest[1] << 8) |
            ((uint32_t)digest[2] << 16) | ((uint32_t)digest[3] << 24);
    value %= 1000000u;

    out[CAIRN_SAFETY_CODE_DIGITS] = '\0';
    for (i = CAIRN_SAFETY_CODE_DIGITS - 1; i >= 0; i--) {
        out[i] = (char)('0' + (value % 10u));
        value /= 10u;
    }
    cairn_memzero(digest, sizeof digest);
    return CAIRN_OK;
}

int cairn_fingerprint_text(char out[18], const uint8_t fp[CAIRN_FP_BYTES])
{
    static const char hex[] = "0123456789abcdef";
    int i, o = 0;

    if (out == NULL || fp == NULL) return CAIRN_ERR_ARG;

    /* Six groups of two bytes keeps the string short enough to read out loud
     * yet long enough to compare without truncation ambiguity. */
    for (i = 0; i < 6; i++) {
        if (i > 0) out[o++] = ':';
        out[o++] = hex[(fp[i] >> 4) & 0x0f];
        out[o++] = hex[fp[i] & 0x0f];
    }
    out[o] = '\0';
    return CAIRN_OK;
}

int cairn_pubkey_encode(uint8_t out[CAIRN_PUBKEY_BYTES], const cairn_pubkey *pk)
{
    size_t o = 0;

    if (out == NULL || pk == NULL) return CAIRN_ERR_ARG;
    memcpy(out + o, pk->id, CAIRN_ID_BYTES);
    o += CAIRN_ID_BYTES;
    memcpy(out + o, pk->ed_pub, CAIRN_ED25519_PUB_BYTES);
    o += CAIRN_ED25519_PUB_BYTES;
    memcpy(out + o, pk->dh_pub, CAIRN_X25519_BYTES);
    o += CAIRN_X25519_BYTES;
    memcpy(out + o, pk->kem_pub, CAIRN_MLKEM_PUB_BYTES);
    return CAIRN_OK;
}

int cairn_pubkey_decode(cairn_pubkey *pk, const uint8_t in[CAIRN_PUBKEY_BYTES])
{
    size_t o = 0;

    if (pk == NULL || in == NULL) return CAIRN_ERR_ARG;
    memcpy(pk->id, in + o, CAIRN_ID_BYTES);
    o += CAIRN_ID_BYTES;
    memcpy(pk->ed_pub, in + o, CAIRN_ED25519_PUB_BYTES);
    o += CAIRN_ED25519_PUB_BYTES;
    memcpy(pk->dh_pub, in + o, CAIRN_X25519_BYTES);
    o += CAIRN_X25519_BYTES;
    memcpy(pk->kem_pub, in + o, CAIRN_MLKEM_PUB_BYTES);
    return CAIRN_OK;
}