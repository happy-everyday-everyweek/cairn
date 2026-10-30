#include "test.h"

#include "cairn/crypto.h"

CT_TEST(mlkem768_roundtrip_shares_secret)
{
    uint8_t pk[CAIRN_MLKEM_PUB_BYTES];
    uint8_t sk[CAIRN_MLKEM_SEC_BYTES];
    uint8_t ct[CAIRN_MLKEM_CT_BYTES];
    uint8_t ss_sender[CAIRN_MLKEM_SS_BYTES];
    uint8_t ss_receiver[CAIRN_MLKEM_SS_BYTES];

    CT_ASSERT_EQ_INT(cairn_mlkem768_keypair(pk, sk), CAIRN_OK);
    CT_ASSERT_EQ_INT(cairn_mlkem768_encaps(ct, ss_sender, pk), CAIRN_OK);
    CT_ASSERT_EQ_INT(cairn_mlkem768_decaps(ss_receiver, ct, sk), CAIRN_OK);
    CT_ASSERT_MEM_EQ(ss_sender, ss_receiver, CAIRN_MLKEM_SS_BYTES);
}

CT_TEST(mlkem768_wrong_key_gives_different_secret)
{
    uint8_t pk[CAIRN_MLKEM_PUB_BYTES];
    uint8_t sk[CAIRN_MLKEM_SEC_BYTES];
    uint8_t other_pk[CAIRN_MLKEM_PUB_BYTES];
    uint8_t other_sk[CAIRN_MLKEM_SEC_BYTES];
    uint8_t ct[CAIRN_MLKEM_CT_BYTES];
    uint8_t ss_sender[CAIRN_MLKEM_SS_BYTES];
    uint8_t ss_wrong[CAIRN_MLKEM_SS_BYTES];

    CT_ASSERT_EQ_INT(cairn_mlkem768_keypair(pk, sk), CAIRN_OK);
    CT_ASSERT_EQ_INT(cairn_mlkem768_keypair(other_pk, other_sk), CAIRN_OK);
    CT_ASSERT_EQ_INT(cairn_mlkem768_encaps(ct, ss_sender, pk), CAIRN_OK);
    CT_ASSERT_EQ_INT(cairn_mlkem768_decaps(ss_wrong, ct, other_sk), CAIRN_OK);
    CT_ASSERT(memcmp(ss_sender, ss_wrong, CAIRN_MLKEM_SS_BYTES) != 0);
}

CT_TEST(mlkem768_two_keypairs_differ)
{
    uint8_t a_pk[CAIRN_MLKEM_PUB_BYTES];
    uint8_t a_sk[CAIRN_MLKEM_SEC_BYTES];
    uint8_t b_pk[CAIRN_MLKEM_PUB_BYTES];
    uint8_t b_sk[CAIRN_MLKEM_SEC_BYTES];

    CT_ASSERT_EQ_INT(cairn_mlkem768_keypair(a_pk, a_sk), CAIRN_OK);
    CT_ASSERT_EQ_INT(cairn_mlkem768_keypair(b_pk, b_sk), CAIRN_OK);
    CT_ASSERT(memcmp(a_pk, b_pk, CAIRN_MLKEM_PUB_BYTES) != 0);
}

void ct_reg_kem(void)
{
    CT_REG(mlkem768_roundtrip_shares_secret);
    CT_REG(mlkem768_wrong_key_gives_different_secret);
    CT_REG(mlkem768_two_keypairs_differ);
}
