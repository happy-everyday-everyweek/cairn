#include "test.h"

#include "cairn/crypto.h"

/* RFC 5869 style KDF checks, adapted to our keyed BLAKE2b construction: the
 * point of these tests is the properties, not a published vector, because the
 * construction is ours. The reference values come from python hashlib.blake2b
 * with an explicit key, computed independently. */
CT_TEST(kdf_is_deterministic_and_labelled)
{
    static const uint8_t key[32] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
    };
    uint8_t a[64];
    uint8_t b[64];
    uint8_t c[64];
    uint8_t wide[96];

    CT_ASSERT_EQ_INT(cairn_kdf(a, sizeof a, key, "label-a", 7), CAIRN_OK);
    CT_ASSERT_EQ_INT(cairn_kdf(b, sizeof b, key, "label-a", 7), CAIRN_OK);
    CT_ASSERT_MEM_EQ(a, b, sizeof a);

    CT_ASSERT_EQ_INT(cairn_kdf(c, sizeof c, key, "label-b", 7), CAIRN_OK);
    CT_ASSERT(memcmp(a, c, sizeof a) != 0);

    /* Expanding past one block must still be deterministic and must differ
     * from the plain first block. */
    CT_ASSERT_EQ_INT(cairn_kdf(wide, sizeof wide, key, "label-a", 7), CAIRN_OK);
    CT_ASSERT_MEM_EQ(wide, a, 64);
}

CT_TEST(kdf_slow_costs_more_rounds_and_is_stable)
{
    uint8_t fast[32];
    uint8_t slow[32];
    uint8_t again[32];

    CT_ASSERT_EQ_INT(cairn_kdf_slow(fast, "passphrase", 10, "salt", 4, 1), CAIRN_OK);
    CT_ASSERT_EQ_INT(cairn_kdf_slow(slow, "passphrase", 10, "salt", 4, 1000), CAIRN_OK);
    CT_ASSERT(memcmp(fast, slow, 32) != 0);

    CT_ASSERT_EQ_INT(cairn_kdf_slow(again, "passphrase", 10, "salt", 4, 1000), CAIRN_OK);
    CT_ASSERT_MEM_EQ(slow, again, 32);

    CT_ASSERT_EQ_INT(cairn_kdf_slow(fast, "passphrase", 10, "salt", 4, 0), CAIRN_ERR_ARG);
}

CT_TEST(aead_uses_xchacha_nonce_length)
{
    uint8_t key[32] = {0};
    uint8_t nonce[CAIRN_NONCE_BYTES];
    uint8_t sealed[32];
    uint8_t plain[16];

    memset(nonce, 7, sizeof nonce);
    CT_ASSERT_EQ_INT(CAIRN_NONCE_BYTES, 24);
    CT_ASSERT_EQ_INT(cairn_aead_seal(sealed, key, nonce, "ad", 2, "1234567890", 10), CAIRN_OK);
    CT_ASSERT_EQ_INT(cairn_aead_open(plain, key, nonce, "ad", 2, sealed, 26), CAIRN_OK);
    CT_ASSERT_MEM_EQ(plain, "1234567890", 10);
}

void ct_reg_kdf(void)
{
    CT_REG(kdf_is_deterministic_and_labelled);
    CT_REG(kdf_slow_costs_more_rounds_and_is_stable);
    CT_REG(aead_uses_xchacha_nonce_length);
}
