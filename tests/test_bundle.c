#include "test.h"

#include <string.h>

#include "cairn/bundle.h"
#include "cairn/crypto.h"
#include "cairn/identity.h"

/* A bundle must round trip between exactly the two identities involved. */
CT_TEST(bundle_roundtrip)
{
    cairn_identity alice, bob;
    cairn_pubkey bob_pub;
    uint8_t plain[500];
    uint8_t sealed[4096];
    uint8_t opened[4096];
    size_t sealed_len = 0, opened_len = 0;
    size_t i;

    CT_ASSERT_EQ_INT(cairn_identity_generate(&alice), CAIRN_OK);
    CT_ASSERT_EQ_INT(cairn_identity_generate(&bob), CAIRN_OK);
    CT_ASSERT_EQ_INT(cairn_identity_pubkey(&bob, &bob_pub), CAIRN_OK);

    for (i = 0; i < sizeof plain; i++) plain[i] = (uint8_t)(i * 7 + 3);

    CT_ASSERT(cairn_bundle_size(sizeof plain) <= sizeof sealed);
    CT_ASSERT_EQ_INT(cairn_seal(sealed, sizeof sealed, &sealed_len, &alice, &bob_pub,
                                plain, sizeof plain), CAIRN_OK);

    CT_ASSERT_EQ_INT(cairn_unseal(opened, sizeof opened, &opened_len, &bob,
                                  sealed, sealed_len), CAIRN_OK);
    CT_ASSERT_EQ_INT(opened_len, sizeof plain);
    CT_ASSERT_MEM_EQ(opened, plain, sizeof plain);

    cairn_identity_clear(&alice);
    cairn_identity_clear(&bob);
}

/* The whole point of recipient binding: a third device gets nothing. */
CT_TEST(bundle_wrong_recipient_rejected)
{
    cairn_identity alice, bob, eve;
    cairn_pubkey bob_pub;
    uint8_t sealed[2048];
    uint8_t opened[2048];
    size_t sealed_len = 0, opened_len = 0;

    CT_ASSERT_EQ_INT(cairn_identity_generate(&alice), CAIRN_OK);
    CT_ASSERT_EQ_INT(cairn_identity_generate(&bob), CAIRN_OK);
    CT_ASSERT_EQ_INT(cairn_identity_generate(&eve), CAIRN_OK);
    CT_ASSERT_EQ_INT(cairn_identity_pubkey(&bob, &bob_pub), CAIRN_OK);

    CT_ASSERT_EQ_INT(cairn_seal(sealed, sizeof sealed, &sealed_len, &alice, &bob_pub,
                                "for bob only", 12), CAIRN_OK);

    /* Eve must fail, and fail loudly rather than returning garbage. */
    CT_ASSERT_EQ_INT(cairn_unseal(opened, sizeof opened, &opened_len, &eve,
                                  sealed, sealed_len), CAIRN_ERR_AUTH);

    cairn_identity_clear(&alice);
    cairn_identity_clear(&bob);
    cairn_identity_clear(&eve);
}

/* A flipped bit anywhere must be caught, because every chunk carries a tag and the
 * whole file carries a signature. */
CT_TEST(bundle_tamper_rejected)
{
    cairn_identity alice, bob;
    cairn_pubkey bob_pub;
    uint8_t sealed[2048];
    uint8_t copy[2048];
    uint8_t opened[2048];
    size_t sealed_len = 0, opened_len = 0;
    size_t step;
    static const char body[] =
        "0123456789012345678901234567890123456789012345678901234567890123456789"
        "0123456789012345678901234567890123456789012345678901234567890123456789";

    CT_ASSERT_EQ_INT(cairn_identity_generate(&alice), CAIRN_OK);
    CT_ASSERT_EQ_INT(cairn_identity_generate(&bob), CAIRN_OK);
    CT_ASSERT_EQ_INT(cairn_identity_pubkey(&bob, &bob_pub), CAIRN_OK);

    CT_ASSERT_EQ_INT(cairn_seal(sealed, sizeof sealed, &sealed_len, &alice, &bob_pub,
                                body, sizeof body - 1), CAIRN_OK);

    /* Walk across the header and most of the body. */
    for (step = 0; step < sealed_len; step += 23) {
        int rc;
        memcpy(copy, sealed, sealed_len);
        copy[step] ^= 0x40;
        rc = cairn_unseal(opened, sizeof opened, &opened_len, &bob, copy, sealed_len);
        CT_ASSERT(rc != CAIRN_OK);
    }

    cairn_identity_clear(&alice);
    cairn_identity_clear(&bob);
}

/* Two bundles of the same plaintext must look unrelated, so a cloud provider cannot
 * tell the same file was uploaded twice. */
CT_TEST(bundle_is_randomised)
{
    cairn_identity alice, bob;
    cairn_pubkey bob_pub;
    uint8_t one[2048], two[2048];
    size_t len_one = 0, len_two = 0;

    CT_ASSERT_EQ_INT(cairn_identity_generate(&alice), CAIRN_OK);
    CT_ASSERT_EQ_INT(cairn_identity_generate(&bob), CAIRN_OK);
    CT_ASSERT_EQ_INT(cairn_identity_pubkey(&bob, &bob_pub), CAIRN_OK);

    CT_ASSERT_EQ_INT(cairn_seal(one, sizeof one, &len_one, &alice, &bob_pub, "same", 4),
                     CAIRN_OK);
    CT_ASSERT_EQ_INT(cairn_seal(two, sizeof two, &len_two, &alice, &bob_pub, "same", 4),
                     CAIRN_OK);
    CT_ASSERT_EQ_INT(len_one, len_two);
    CT_ASSERT(!cairn_memeq(one, two, len_one));

    cairn_identity_clear(&alice);
    cairn_identity_clear(&bob);
}

/* A bundle larger than one chunk must stream chunk by chunk and reassemble. */
CT_TEST(bundle_multi_chunk)
{
    static cairn_identity alice, bob;
    static cairn_pubkey bob_pub;
    static uint8_t plain[CAIRN_BUNDLE_CHUNK * 2 + 1234];
    static uint8_t sealed[CAIRN_BUNDLE_CHUNK * 3 + 4096];
    static uint8_t opened[sizeof plain];
    size_t sealed_len = 0, opened_len = 0;
    size_t i;

    CT_ASSERT_EQ_INT(cairn_identity_generate(&alice), CAIRN_OK);
    CT_ASSERT_EQ_INT(cairn_identity_generate(&bob), CAIRN_OK);
    CT_ASSERT_EQ_INT(cairn_identity_pubkey(&bob, &bob_pub), CAIRN_OK);

    for (i = 0; i < sizeof plain; i++) plain[i] = (uint8_t)(i ^ 0x5a);

    CT_ASSERT(cairn_bundle_size(sizeof plain) <= sizeof sealed);
    CT_ASSERT_EQ_INT(cairn_seal(sealed, sizeof sealed, &sealed_len, &alice, &bob_pub,
                                plain, sizeof plain), CAIRN_OK);
    CT_ASSERT_EQ_INT(cairn_unseal(opened, sizeof opened, &opened_len, &bob,
                                  sealed, sealed_len), CAIRN_OK);
    CT_ASSERT_EQ_INT(opened_len, sizeof plain);
    CT_ASSERT_MEM_EQ(opened, plain, sizeof plain);

    cairn_identity_clear(&alice);
    cairn_identity_clear(&bob);
}

/* The header alone is enough to learn the shape, which is what a downloader wants
 * before allocating anything. */
CT_TEST(bundle_peek_reports_shape)
{
    cairn_identity alice, bob;
    cairn_pubkey bob_pub;
    uint8_t sealed[2048];
    size_t sealed_len = 0;
    cairn_bundle_info info;

    CT_ASSERT_EQ_INT(cairn_identity_generate(&alice), CAIRN_OK);
    CT_ASSERT_EQ_INT(cairn_identity_generate(&bob), CAIRN_OK);
    CT_ASSERT_EQ_INT(cairn_identity_pubkey(&bob, &bob_pub), CAIRN_OK);

    CT_ASSERT_EQ_INT(cairn_seal(sealed, sizeof sealed, &sealed_len, &alice, &bob_pub,
                                "shape", 5), CAIRN_OK);

    /* Only the header bytes are needed, not the whole bundle. */
    CT_ASSERT_EQ_INT(cairn_bundle_peek(&info, sealed, CAIRN_BUNDLE_HEADER_BYTES),
                     CAIRN_OK);
    CT_ASSERT_EQ_INT(info.plaintext_len, 5);
    CT_ASSERT_EQ_INT(info.chunk_count, 1);
    CT_ASSERT_EQ_INT(info.chunk_size, CAIRN_BUNDLE_CHUNK);

    /* And it identifies the sender by public key. */
    CT_ASSERT_MEM_EQ(info.sender.id, alice.id, CAIRN_ID_BYTES);

    cairn_identity_clear(&alice);
    cairn_identity_clear(&bob);
}

/* Truncating a bundle, or lying about its length, must be refused. */
CT_TEST(bundle_truncated_rejected)
{
    cairn_identity alice, bob;
    cairn_pubkey bob_pub;
    uint8_t sealed[2048];
    uint8_t opened[2048];
    size_t sealed_len = 0, opened_len = 0;

    CT_ASSERT_EQ_INT(cairn_identity_generate(&alice), CAIRN_OK);
    CT_ASSERT_EQ_INT(cairn_identity_generate(&bob), CAIRN_OK);
    CT_ASSERT_EQ_INT(cairn_identity_pubkey(&bob, &bob_pub), CAIRN_OK);

    CT_ASSERT_EQ_INT(cairn_seal(sealed, sizeof sealed, &sealed_len, &alice, &bob_pub,
                                "truncate me", 11), CAIRN_OK);

    CT_ASSERT_EQ_INT(cairn_unseal(opened, sizeof opened, &opened_len, &bob,
                                  sealed, sealed_len - 1), CAIRN_ERR_FORMAT);
    CT_ASSERT_EQ_INT(cairn_unseal(opened, sizeof opened, &opened_len, &bob,
                                  sealed, CAIRN_BUNDLE_HEADER_BYTES - 1), CAIRN_ERR_FORMAT);

    cairn_identity_clear(&alice);
    cairn_identity_clear(&bob);
}

CT_TEST(bundle_args_rejected)
{
    cairn_identity alice, bob;
    cairn_pubkey bob_pub;
    uint8_t buf[512];
    size_t len = 0;

    CT_ASSERT_EQ_INT(cairn_identity_generate(&alice), CAIRN_OK);
    CT_ASSERT_EQ_INT(cairn_identity_generate(&bob), CAIRN_OK);
    CT_ASSERT_EQ_INT(cairn_identity_pubkey(&bob, &bob_pub), CAIRN_OK);

    CT_ASSERT_EQ_INT(cairn_seal(NULL, sizeof buf, &len, &alice, &bob_pub, "x", 1),
                     CAIRN_ERR_ARG);
    CT_ASSERT_EQ_INT(cairn_seal(buf, sizeof buf, &len, NULL, &bob_pub, "x", 1),
                     CAIRN_ERR_ARG);
    CT_ASSERT_EQ_INT(cairn_seal(buf, sizeof buf, &len, &alice, NULL, "x", 1),
                     CAIRN_ERR_ARG);
    /* Zero length is not a valid bundle. */
    CT_ASSERT_EQ_INT(cairn_seal(buf, sizeof buf, &len, &alice, &bob_pub, "x", 0),
                     CAIRN_ERR_ARG);
    /* Too small a buffer is reported, not overrun. */
    CT_ASSERT_EQ_INT(cairn_seal(buf, 16, &len, &alice, &bob_pub, "x", 1),
                     CAIRN_ERR_BUFFER);

    cairn_identity_clear(&alice);
    cairn_identity_clear(&bob);
}

void ct_reg_bundle(void)
{
    CT_REG(bundle_roundtrip);
    CT_REG(bundle_wrong_recipient_rejected);
    CT_REG(bundle_tamper_rejected);
    CT_REG(bundle_is_randomised);
    CT_REG(bundle_multi_chunk);
    CT_REG(bundle_peek_reports_shape);
    CT_REG(bundle_truncated_rejected);
    CT_REG(bundle_args_rejected);
}