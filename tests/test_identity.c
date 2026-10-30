#include "test.h"

#include <string.h>

#include "cairn/identity.h"

CT_TEST(identity_generate_populates_keys)
{
    cairn_identity id;
    cairn_pubkey pk;
    static const uint8_t zero[32] = {0};

    CT_ASSERT_EQ_INT(cairn_identity_generate(&id), CAIRN_OK);
    CT_ASSERT_EQ_INT(cairn_identity_pubkey(&id, &pk), CAIRN_OK);
    CT_ASSERT_MEM_EQ(pk.ed_pub, id.ed_pub, CAIRN_ED25519_PUB_BYTES);
    CT_ASSERT_MEM_EQ(pk.dh_pub, id.dh_pub, CAIRN_X25519_BYTES);
    CT_ASSERT(!cairn_memeq(id.dh_pub, zero, 32));

    cairn_identity_clear(&id);
}

/* Two identities must not share keys, and the id must differ too. */
CT_TEST(identity_generate_is_random)
{
    cairn_identity a, b;

    CT_ASSERT_EQ_INT(cairn_identity_generate(&a), CAIRN_OK);
    CT_ASSERT_EQ_INT(cairn_identity_generate(&b), CAIRN_OK);
    CT_ASSERT(!cairn_memeq(a.ed_pub, b.ed_pub, CAIRN_ED25519_PUB_BYTES));
    CT_ASSERT(!cairn_memeq(a.dh_pub, b.dh_pub, CAIRN_X25519_BYTES));
    CT_ASSERT(!cairn_memeq(a.kem_pub, b.kem_pub, 64));
    CT_ASSERT(!cairn_memeq(a.id, b.id, CAIRN_ID_BYTES));

    cairn_identity_clear(&a);
    cairn_identity_clear(&b);
}

/* The identity key must actually sign, which proves it is internally paired. */
CT_TEST(identity_keys_are_usable)
{
    cairn_identity id;
    cairn_pubkey pk;
    uint8_t sig[CAIRN_ED25519_SIG_BYTES];
    uint8_t shared_a[32], shared_b[32];
    uint8_t x_sec[32], x_pub[32];

    CT_ASSERT_EQ_INT(cairn_identity_generate(&id), CAIRN_OK);
    CT_ASSERT_EQ_INT(cairn_identity_pubkey(&id, &pk), CAIRN_OK);

    CT_ASSERT_EQ_INT(cairn_ed25519_sign(sig, id.ed_sec, "hi", 2), CAIRN_OK);
    CT_ASSERT_EQ_INT(cairn_ed25519_verify(sig, pk.ed_pub, "hi", 2), CAIRN_OK);

    CT_ASSERT_EQ_INT(cairn_x25519_keypair(x_pub, x_sec), CAIRN_OK);
    CT_ASSERT_EQ_INT(cairn_x25519(shared_a, x_sec, pk.dh_pub), CAIRN_OK);
    CT_ASSERT_EQ_INT(cairn_x25519(shared_b, id.dh_sec, x_pub), CAIRN_OK);
    CT_ASSERT_MEM_EQ(shared_a, shared_b, 32);

    cairn_identity_clear(&id);
}

CT_TEST(identity_fingerprint_stable)
{
    cairn_identity id;
    uint8_t one[CAIRN_FP_BYTES], two[CAIRN_FP_BYTES];

    CT_ASSERT_EQ_INT(cairn_identity_generate(&id), CAIRN_OK);
    CT_ASSERT_EQ_INT(cairn_identity_fingerprint(one, &id), CAIRN_OK);
    CT_ASSERT_EQ_INT(cairn_identity_fingerprint(two, &id), CAIRN_OK);
    CT_ASSERT_MEM_EQ(one, two, CAIRN_FP_BYTES);

    cairn_identity_clear(&id);
}

/* Any change in the public key must change the fingerprint. */
CT_TEST(identity_fingerprint_covers_every_key)
{
    cairn_identity id;
    cairn_pubkey pk;
    uint8_t base[CAIRN_FP_BYTES], other[CAIRN_FP_BYTES];

    CT_ASSERT_EQ_INT(cairn_identity_generate(&id), CAIRN_OK);
    CT_ASSERT_EQ_INT(cairn_identity_pubkey(&id, &pk), CAIRN_OK);
    CT_ASSERT_EQ_INT(cairn_pubkey_fingerprint(base, &pk), CAIRN_OK);

    pk.ed_pub[0] ^= 1;
    CT_ASSERT_EQ_INT(cairn_pubkey_fingerprint(other, &pk), CAIRN_OK);
    CT_ASSERT(!cairn_memeq(base, other, CAIRN_FP_BYTES));
    pk.ed_pub[0] ^= 1;

    pk.dh_pub[5] ^= 1;
    CT_ASSERT_EQ_INT(cairn_pubkey_fingerprint(other, &pk), CAIRN_OK);
    CT_ASSERT(!cairn_memeq(base, other, CAIRN_FP_BYTES));
    pk.dh_pub[5] ^= 1;

    pk.kem_pub[100] ^= 1;
    CT_ASSERT_EQ_INT(cairn_pubkey_fingerprint(other, &pk), CAIRN_OK);
    CT_ASSERT(!cairn_memeq(base, other, CAIRN_FP_BYTES));
    pk.kem_pub[100] ^= 1;

    pk.id[3] ^= 1;
    CT_ASSERT_EQ_INT(cairn_pubkey_fingerprint(other, &pk), CAIRN_OK);
    CT_ASSERT(!cairn_memeq(base, other, CAIRN_FP_BYTES));

    cairn_identity_clear(&id);
}

/* Both peers must arrive at the same six digits without agreeing an order. */
CT_TEST(safety_code_symmetric)
{
    cairn_identity a, b;
    uint8_t fp_a[CAIRN_FP_BYTES], fp_b[CAIRN_FP_BYTES];
    char code_ab[CAIRN_SAFETY_CODE_BYTES], code_ba[CAIRN_SAFETY_CODE_BYTES];
    int i;

    CT_ASSERT_EQ_INT(cairn_identity_generate(&a), CAIRN_OK);
    CT_ASSERT_EQ_INT(cairn_identity_generate(&b), CAIRN_OK);
    CT_ASSERT_EQ_INT(cairn_identity_fingerprint(fp_a, &a), CAIRN_OK);
    CT_ASSERT_EQ_INT(cairn_identity_fingerprint(fp_b, &b), CAIRN_OK);

    CT_ASSERT_EQ_INT(cairn_safety_code(code_ab, fp_a, fp_b), CAIRN_OK);
    CT_ASSERT_EQ_INT(cairn_safety_code(code_ba, fp_b, fp_a), CAIRN_OK);
    CT_ASSERT_MEM_EQ(code_ab, code_ba, CAIRN_SAFETY_CODE_BYTES);
    CT_ASSERT_EQ_INT((int)strlen(code_ab), CAIRN_SAFETY_CODE_DIGITS);

    for (i = 0; i < CAIRN_SAFETY_CODE_DIGITS; i++)
        CT_ASSERT(code_ab[i] >= '0' && code_ab[i] <= '9');

    cairn_identity_clear(&a);
    cairn_identity_clear(&b);
}

/* A one bit change in either fingerprint must change the code almost always.
 * A single pair could collide, so this walks several derived fingerprints. */
CT_TEST(safety_code_changes_with_input)
{
    cairn_identity a, b;
    uint8_t fp_a[CAIRN_FP_BYTES], fp_b[CAIRN_FP_BYTES], fp_c[CAIRN_FP_BYTES];
    char base[CAIRN_SAFETY_CODE_BYTES], other[CAIRN_SAFETY_CODE_BYTES];
    int changed = 0;

    CT_ASSERT_EQ_INT(cairn_identity_generate(&a), CAIRN_OK);
    CT_ASSERT_EQ_INT(cairn_identity_generate(&b), CAIRN_OK);
    CT_ASSERT_EQ_INT(cairn_identity_fingerprint(fp_a, &a), CAIRN_OK);
    CT_ASSERT_EQ_INT(cairn_identity_fingerprint(fp_b, &b), CAIRN_OK);
    CT_ASSERT_EQ_INT(cairn_safety_code(base, fp_a, fp_b), CAIRN_OK);

    for (int i = 0; i < 8; i++) {
        memcpy(fp_c, fp_b, CAIRN_FP_BYTES);
        fp_c[i] ^= 0x80;
        CT_ASSERT_EQ_INT(cairn_safety_code(other, fp_a, fp_c), CAIRN_OK);
        if (memcmp(base, other, CAIRN_SAFETY_CODE_DIGITS) != 0) changed++;
    }
    CT_ASSERT(changed >= 7);

    cairn_identity_clear(&a);
    cairn_identity_clear(&b);
}

CT_TEST(fingerprint_text_format)
{
    cairn_identity id;
    uint8_t fp[CAIRN_FP_BYTES];
    char text[18];

    CT_ASSERT_EQ_INT(cairn_identity_generate(&id), CAIRN_OK);
    CT_ASSERT_EQ_INT(cairn_identity_fingerprint(fp, &id), CAIRN_OK);
    CT_ASSERT_EQ_INT(cairn_fingerprint_text(text, fp), CAIRN_OK);
    CT_ASSERT_EQ_INT((int)strlen(text), 17);
    CT_ASSERT_EQ_INT(text[2], ':');
    CT_ASSERT_EQ_INT(text[5], ':');
    CT_ASSERT_EQ_INT(text[8], ':');
    CT_ASSERT_EQ_INT(text[11], ':');
    CT_ASSERT_EQ_INT(text[14], ':');

    cairn_identity_clear(&id);
}

CT_TEST(pubkey_encode_roundtrip)
{
    cairn_identity id;
    cairn_pubkey pk, back;
    uint8_t wire[CAIRN_PUBKEY_BYTES];
    uint8_t fp_one[CAIRN_FP_BYTES], fp_two[CAIRN_FP_BYTES];

    CT_ASSERT_EQ_INT(cairn_identity_generate(&id), CAIRN_OK);
    CT_ASSERT_EQ_INT(cairn_identity_pubkey(&id, &pk), CAIRN_OK);
    CT_ASSERT_EQ_INT(cairn_pubkey_encode(wire, &pk), CAIRN_OK);
    CT_ASSERT_EQ_INT(cairn_pubkey_decode(&back, wire), CAIRN_OK);
    CT_ASSERT_MEM_EQ(pk.id, back.id, CAIRN_ID_BYTES);
    CT_ASSERT_MEM_EQ(pk.ed_pub, back.ed_pub, CAIRN_ED25519_PUB_BYTES);
    CT_ASSERT_MEM_EQ(pk.dh_pub, back.dh_pub, CAIRN_X25519_BYTES);
    CT_ASSERT_MEM_EQ(pk.kem_pub, back.kem_pub, CAIRN_MLKEM_PUB_BYTES);
    CT_ASSERT_EQ_INT(cairn_pubkey_fingerprint(fp_one, &pk), CAIRN_OK);
    CT_ASSERT_EQ_INT(cairn_pubkey_fingerprint(fp_two, &back), CAIRN_OK);
    CT_ASSERT_MEM_EQ(fp_one, fp_two, CAIRN_FP_BYTES);

    cairn_identity_clear(&id);
}

CT_TEST(identity_clear_wipes_secrets)
{
    cairn_identity id;
    uint8_t ed_sec_copy[CAIRN_ED25519_SEC_BYTES];
    static const uint8_t zero_key[CAIRN_KEY_BYTES] = {0};
    int all_zero = 1;
    size_t i;

    CT_ASSERT_EQ_INT(cairn_identity_generate(&id), CAIRN_OK);
    memcpy(ed_sec_copy, id.ed_sec, sizeof ed_sec_copy);
    cairn_identity_clear(&id);
    CT_ASSERT(!cairn_memeq(id.ed_sec, ed_sec_copy, CAIRN_ED25519_SEC_BYTES));
    for (i = 0; i < CAIRN_X25519_BYTES; i++)
        if (id.dh_sec[i] != 0) all_zero = 0;
    CT_ASSERT(all_zero);
    (void)zero_key;
}

void ct_reg_identity(void)
{
    CT_REG(identity_generate_populates_keys);
    CT_REG(identity_generate_is_random);
    CT_REG(identity_keys_are_usable);
    CT_REG(identity_fingerprint_stable);
    CT_REG(identity_fingerprint_covers_every_key);
    CT_REG(safety_code_symmetric);
    CT_REG(safety_code_changes_with_input);
    CT_REG(fingerprint_text_format);
    CT_REG(pubkey_encode_roundtrip);
    CT_REG(identity_clear_wipes_secrets);
}
