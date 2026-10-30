#include "test.h"

#include <string.h>

#include "cairn/nested.h"

/* Two peers sharing a passphrase must derive the same session. */
CT_TEST(nested_same_password_same_keys)
{
    cairn_nested a, b;
    uint8_t salt[16];

    memset(salt, 0x5a, sizeof salt);
    CT_ASSERT_EQ_INT(cairn_nested_from_password(&a, "correct horse", 13, salt), CAIRN_OK);
    CT_ASSERT_EQ_INT(cairn_nested_from_password(&b, "correct horse", 13, salt), CAIRN_OK);
    CT_ASSERT_MEM_EQ(a.key, b.key, CAIRN_KEY_BYTES);

    cairn_nested_clear(&a);
    cairn_nested_clear(&b);
}

CT_TEST(nested_different_password_differs)
{
    cairn_nested a, b;
    uint8_t salt[16];

    memset(salt, 0x11, sizeof salt);
    CT_ASSERT_EQ_INT(cairn_nested_from_password(&a, "alpha", 5, salt), CAIRN_OK);
    CT_ASSERT_EQ_INT(cairn_nested_from_password(&b, "beta", 4, salt), CAIRN_OK);
    CT_ASSERT(!cairn_memeq(a.key, b.key, CAIRN_KEY_BYTES));

    CT_ASSERT_EQ_INT(cairn_nested_from_password(&b, "alpha", 5, salt), CAIRN_OK);
    CT_ASSERT(cairn_memeq(a.key, b.key, CAIRN_KEY_BYTES));

    cairn_nested_clear(&a);
    cairn_nested_clear(&b);
}

CT_TEST(nested_salt_changes_key)
{
    cairn_nested a, b;
    uint8_t salt_a[16], salt_b[16];

    memset(salt_a, 0x01, sizeof salt_a);
    memset(salt_b, 0x02, sizeof salt_b);
    CT_ASSERT_EQ_INT(cairn_nested_from_password(&a, "pw", 2, salt_a), CAIRN_OK);
    CT_ASSERT_EQ_INT(cairn_nested_from_password(&b, "pw", 2, salt_b), CAIRN_OK);
    CT_ASSERT(!cairn_memeq(a.key, b.key, CAIRN_KEY_BYTES));

    cairn_nested_clear(&a);
    cairn_nested_clear(&b);
}

CT_TEST(nested_seal_open_roundtrip)
{
    cairn_nested n;
    uint8_t salt[16];
    uint8_t sealed[256];
    uint8_t opened[256];
    size_t sealed_len = 0, opened_len = 0;
    size_t room;

    memset(salt, 0x7f, sizeof salt);
    CT_ASSERT_EQ_INT(cairn_nested_from_password(&n, "hunter2", 7, salt), CAIRN_OK);

    room = cairn_nested_sealed_size(11);
    CT_ASSERT(room <= sizeof sealed);
    CT_ASSERT_EQ_INT(cairn_nested_seal(&n, sealed, sizeof sealed, &sealed_len,
                                       "hello cairn", 11), CAIRN_OK);
    CT_ASSERT_EQ_INT(sealed_len, room);

    CT_ASSERT_EQ_INT(cairn_nested_open(&n, opened, sizeof opened, &opened_len,
                                       sealed, sealed_len), CAIRN_OK);
    CT_ASSERT_EQ_INT(opened_len, 11);
    CT_ASSERT_MEM_EQ(opened, "hello cairn", 11);

    cairn_nested_clear(&n);
}

/* The same plaintext sealed twice must not produce the same bytes. */
CT_TEST(nested_seal_is_randomised)
{
    cairn_nested n;
    uint8_t salt[16];
    uint8_t one[256], two[256];
    size_t len_one = 0, len_two = 0;

    memset(salt, 0x33, sizeof salt);
    CT_ASSERT_EQ_INT(cairn_nested_from_password(&n, "pw", 2, salt), CAIRN_OK);

    CT_ASSERT_EQ_INT(cairn_nested_seal(&n, one, sizeof one, &len_one, "abc", 3), CAIRN_OK);
    CT_ASSERT_EQ_INT(cairn_nested_seal(&n, two, sizeof two, &len_two, "abc", 3), CAIRN_OK);
    CT_ASSERT_EQ_INT(len_one, len_two);
    CT_ASSERT(!cairn_memeq(one, two, len_one));

    cairn_nested_clear(&n);
}

/* Length leaks only the padded bucket, not the exact plaintext length. */
CT_TEST(nested_length_is_coarse)
{
    cairn_nested n;
    uint8_t salt[16];

    memset(salt, 0x44, sizeof salt);
    CT_ASSERT_EQ_INT(cairn_nested_from_password(&n, "pw", 2, salt), CAIRN_OK);

    CT_ASSERT_EQ_INT(cairn_nested_sealed_size(0), cairn_nested_sealed_size(1));
    CT_ASSERT_EQ_INT(cairn_nested_sealed_size(3), cairn_nested_sealed_size(50));
    CT_ASSERT_EQ_INT(cairn_nested_sealed_size(50), cairn_nested_sealed_size(51));
    CT_ASSERT_EQ_INT(cairn_nested_sealed_size(52), cairn_nested_sealed_size(63));
    CT_ASSERT(cairn_nested_sealed_size(64) > cairn_nested_sealed_size(63));
    CT_ASSERT_EQ_INT(cairn_nested_sealed_size(64), cairn_nested_sealed_size(65));
    CT_ASSERT_EQ_INT(cairn_nested_sealed_size(64), cairn_nested_sealed_size(127));
    CT_ASSERT(cairn_nested_sealed_size(128) > cairn_nested_sealed_size(127));

    cairn_nested_clear(&n);
}

/* A flipped byte anywhere in the blob must be rejected. */
CT_TEST(nested_tamper_is_rejected)
{
    cairn_nested n;
    uint8_t salt[16];
    uint8_t sealed[256];
    uint8_t opened[256];
    size_t sealed_len = 0, opened_len = 0;
    size_t i;

    memset(salt, 0x55, sizeof salt);
    CT_ASSERT_EQ_INT(cairn_nested_from_password(&n, "pw", 2, salt), CAIRN_OK);
    CT_ASSERT_EQ_INT(cairn_nested_seal(&n, sealed, sizeof sealed, &sealed_len,
                                       "payload", 7), CAIRN_OK);

    for (i = 0; i < sealed_len; i += 7) {
        uint8_t copy[256];
        int rc;
        memcpy(copy, sealed, sealed_len);
        copy[i] ^= 0x01;
        rc = cairn_nested_open(&n, opened, sizeof opened, &opened_len, copy, sealed_len);
        CT_ASSERT(rc != CAIRN_OK);
    }

    cairn_nested_clear(&n);
}

/* A peer with the wrong passphrase cannot open the blob. */
CT_TEST(nested_wrong_key_rejected)
{
    cairn_nested good, bad;
    uint8_t salt[16];
    uint8_t sealed[256];
    uint8_t opened[256];
    size_t sealed_len = 0, opened_len = 0;

    memset(salt, 0x66, sizeof salt);
    CT_ASSERT_EQ_INT(cairn_nested_from_password(&good, "right", 5, salt), CAIRN_OK);
    CT_ASSERT_EQ_INT(cairn_nested_from_password(&bad, "wrong", 5, salt), CAIRN_OK);
    CT_ASSERT_EQ_INT(cairn_nested_seal(&good, sealed, sizeof sealed, &sealed_len,
                                       "secret", 6), CAIRN_OK);
    CT_ASSERT_EQ_INT(cairn_nested_open(&bad, opened, sizeof opened, &opened_len,
                                       sealed, sealed_len), CAIRN_ERR_AUTH);

    cairn_nested_clear(&good);
    cairn_nested_clear(&bad);
}

/* A buffer that is too small must be reported, not overrun. */
CT_TEST(nested_short_buffer_rejected)
{
    cairn_nested n;
    uint8_t salt[16];
    uint8_t sealed[256];
    uint8_t tiny[8];
    size_t sealed_len = 0, outlen = 0;

    memset(salt, 0x77, sizeof salt);
    CT_ASSERT_EQ_INT(cairn_nested_from_password(&n, "pw", 2, salt), CAIRN_OK);
    CT_ASSERT_EQ_INT(cairn_nested_seal(&n, sealed, sizeof sealed, &sealed_len,
                                       "abcdefghij", 10), CAIRN_OK);

    CT_ASSERT_EQ_INT(cairn_nested_seal(&n, tiny, sizeof tiny, &outlen,
                                       "abcdefghij", 10), CAIRN_ERR_BUFFER);
    CT_ASSERT_EQ_INT(cairn_nested_open(&n, tiny, sizeof tiny, &outlen,
                                       sealed, sealed_len), CAIRN_ERR_BUFFER);
    /* Truncated input is a format error, not a crash. */
    CT_ASSERT_EQ_INT(cairn_nested_open(&n, sealed, sizeof sealed, &outlen,
                                       sealed, 4), CAIRN_ERR_FORMAT);

    cairn_nested_clear(&n);
}

CT_TEST(nested_null_args_rejected)
{
    cairn_nested n;
    uint8_t salt[16];
    size_t outlen = 0;

    memset(salt, 0x88, sizeof salt);
    CT_ASSERT_EQ_INT(cairn_nested_from_password(NULL, "pw", 2, salt), CAIRN_ERR_ARG);
    CT_ASSERT_EQ_INT(cairn_nested_from_password(&n, NULL, 2, salt), CAIRN_ERR_ARG);
    CT_ASSERT_EQ_INT(cairn_nested_seal(NULL, salt, 16, &outlen, "x", 1), CAIRN_ERR_ARG);
    CT_ASSERT_EQ_INT(cairn_nested_open(NULL, salt, 16, &outlen, "x", 1), CAIRN_ERR_ARG);
}

void ct_reg_nested(void)
{
    CT_REG(nested_same_password_same_keys);
    CT_REG(nested_different_password_differs);
    CT_REG(nested_salt_changes_key);
    CT_REG(nested_seal_open_roundtrip);
    CT_REG(nested_seal_is_randomised);
    CT_REG(nested_length_is_coarse);
    CT_REG(nested_tamper_is_rejected);
    CT_REG(nested_wrong_key_rejected);
    CT_REG(nested_short_buffer_rejected);
    CT_REG(nested_null_args_rejected);
}
