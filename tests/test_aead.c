#include "test.h"

#include "cairn/crypto.h"

/* XChaCha20-Poly1305 expected bytes from libsodium via python nacl 1.6.2,
 * which is an independent implementation of the same construction. */
CT_TEST(aead_matches_libsodium_vector)
{
    static const uint8_t key[32] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
    };
    static const uint8_t nonce[24] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17
    };
    static const char plaintext[] = "hello cairn protocol";
    static const uint8_t want[36] = {
        0xf6, 0xa7, 0x63, 0x13, 0xff, 0xf2, 0xee, 0xcf,
        0x5a, 0x36, 0x48, 0xee, 0xbb, 0x20, 0xc7, 0x9c,
        0x24, 0x24, 0x47, 0xc9, 0x51, 0xc0, 0x92, 0xa0,
        0xd4, 0x21, 0x33, 0x74, 0xdd, 0x75, 0xd7, 0x83,
        0xd4, 0x99, 0x11, 0x8e
    };
    uint8_t got[36];
    uint8_t back[20];

    CT_ASSERT_EQ_INT(cairn_aead_seal(got, key, nonce, "cairn", 5,
                                     plaintext, sizeof plaintext - 1), CAIRN_OK);
    CT_ASSERT_MEM_EQ(got, want, sizeof want);

    CT_ASSERT_EQ_INT(cairn_aead_open(back, key, nonce, "cairn", 5, got, sizeof got), CAIRN_OK);
    CT_ASSERT_MEM_EQ(back, plaintext, sizeof plaintext - 1);
}

CT_TEST(aead_rejects_tampered_tag)
{
    uint8_t key[32];
    uint8_t nonce[24];
    uint8_t sealed[64];
    uint8_t plain[64];
    int i;

    for (i = 0; i < 32; i++) key[i] = (uint8_t)i;
    for (i = 0; i < 24; i++) nonce[i] = (uint8_t)(0xa0 + i);

    CT_ASSERT_EQ_INT(cairn_aead_seal(sealed, key, nonce, NULL, 0, "hello cairn", 11), CAIRN_OK);
    CT_ASSERT_EQ_INT(cairn_aead_open(plain, key, nonce, NULL, 0, sealed, 27), CAIRN_OK);

    sealed[26] ^= 0x01;
    CT_ASSERT_EQ_INT(cairn_aead_open(plain, key, nonce, NULL, 0, sealed, 27), CAIRN_ERR_AUTH);
}

CT_TEST(aead_rejects_wrong_aad)
{
    uint8_t key[32];
    uint8_t nonce[24];
    uint8_t sealed[64];
    uint8_t plain[64];
    int i;

    for (i = 0; i < 32; i++) key[i] = (uint8_t)(i * 3);
    for (i = 0; i < 24; i++) nonce[i] = (uint8_t)(i + 1);

    CT_ASSERT_EQ_INT(cairn_aead_seal(sealed, key, nonce, "hdr", 3, "payload here", 12), CAIRN_OK);
    CT_ASSERT_EQ_INT(cairn_aead_open(plain, key, nonce, "hdx", 3, sealed, 28), CAIRN_ERR_AUTH);
    CT_ASSERT_EQ_INT(cairn_aead_open(plain, key, nonce, "hdr", 3, sealed, 28), CAIRN_OK);
}

CT_TEST(aead_rejects_short_input)
{
    uint8_t key[32] = {0};
    uint8_t nonce[24] = {0};
    uint8_t plain[8] = {0};

    CT_ASSERT_EQ_INT(cairn_aead_open(plain, key, nonce, NULL, 0, plain, 15), CAIRN_ERR_FORMAT);
}

void ct_reg_aead(void)
{
    CT_REG(aead_matches_libsodium_vector);
    CT_REG(aead_rejects_tampered_tag);
    CT_REG(aead_rejects_wrong_aad);
    CT_REG(aead_rejects_short_input);
}
