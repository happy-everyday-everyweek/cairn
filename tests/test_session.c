#include "test.h"

#include <string.h>

#include "cairn/session.h"

/* Runs a full handshake and returns both established sessions. */
static int handshake(cairn_session *a, cairn_session *b,
                     const cairn_identity *ida, const cairn_identity *idb)
{
    uint8_t init[CAIRN_HANDSHAKE_INIT_BYTES];
    uint8_t resp[CAIRN_HANDSHAKE_RESP_BYTES];
    cairn_pubkey pk_a, pk_b;
    int rc;

    cairn_identity_pubkey(ida, &pk_a);
    cairn_identity_pubkey(idb, &pk_b);

    rc = cairn_session_init(a, ida, &pk_b, init);
    if (rc != CAIRN_OK) return rc;
    rc = cairn_session_respond(b, idb, resp, init, sizeof init);
    if (rc != CAIRN_OK) return rc;
    return cairn_session_finish(a, resp, sizeof resp);
}

CT_TEST(session_handshake_establishes)
{
    cairn_identity ida, idb;
    cairn_session a, b;

    CT_ASSERT_EQ_INT(cairn_identity_generate(&ida), CAIRN_OK);
    CT_ASSERT_EQ_INT(cairn_identity_generate(&idb), CAIRN_OK);
    CT_ASSERT_EQ_INT(handshake(&a, &b, &ida, &idb), CAIRN_OK);
    CT_ASSERT(a.established);
    CT_ASSERT(b.established);

    /* Both sides must agree on the root key at the end of the handshake. */
    CT_ASSERT_MEM_EQ(a.root_key, b.root_key, CAIRN_KEY_BYTES);

    cairn_session_clear(&a);
    cairn_session_clear(&b);
    cairn_identity_clear(&ida);
    cairn_identity_clear(&idb);
}

/* The confirmation tag is the real proof that both sides derived the same
 * keys; it is what a peer must verify before trusting the channel. */
CT_TEST(session_confirm_tag_matches)
{
    cairn_identity ida, idb;
    cairn_session a, b;
    uint8_t tag_a[CAIRN_TAG_BYTES], tag_b[CAIRN_TAG_BYTES];
    uint8_t bad[CAIRN_TAG_BYTES];

    CT_ASSERT_EQ_INT(cairn_identity_generate(&ida), CAIRN_OK);
    CT_ASSERT_EQ_INT(cairn_identity_generate(&idb), CAIRN_OK);
    CT_ASSERT_EQ_INT(handshake(&a, &b, &ida, &idb), CAIRN_OK);

    CT_ASSERT_EQ_INT(cairn_session_confirm_tag(tag_a, &a, "confirm"), CAIRN_OK);
    CT_ASSERT_EQ_INT(cairn_session_confirm_tag(tag_b, &b, "confirm"), CAIRN_OK);
    CT_ASSERT_MEM_EQ(tag_a, tag_b, CAIRN_TAG_BYTES);
    CT_ASSERT_EQ_INT(cairn_session_check_tag(&b, "confirm", tag_a), CAIRN_OK);

    memcpy(bad, tag_a, sizeof bad);
    bad[0] ^= 0xff;
    CT_ASSERT_EQ_INT(cairn_session_check_tag(&b, "confirm", bad), CAIRN_ERR_AUTH);
    /* A different label must not verify with the same tag. */
    CT_ASSERT_EQ_INT(cairn_session_check_tag(&b, "other", tag_a), CAIRN_ERR_AUTH);

    cairn_session_clear(&a);
    cairn_session_clear(&b);
    cairn_identity_clear(&ida);
    cairn_identity_clear(&idb);
}

CT_TEST(session_message_roundtrip)
{
    cairn_identity ida, idb;
    cairn_session a, b;
    cairn_header hdr;
    uint8_t ct[256], pt[256];
    size_t ctlen = 0, ptlen = 0;

    CT_ASSERT_EQ_INT(cairn_identity_generate(&ida), CAIRN_OK);
    CT_ASSERT_EQ_INT(cairn_identity_generate(&idb), CAIRN_OK);
    CT_ASSERT_EQ_INT(handshake(&a, &b, &ida, &idb), CAIRN_OK);

    CT_ASSERT_EQ_INT(cairn_session_seal(&a, &hdr, ct, sizeof ct, &ctlen,
                                        "hello bob", 9), CAIRN_OK);
    CT_ASSERT_EQ_INT(ctlen, 9 + CAIRN_TAG_BYTES);
    CT_ASSERT_EQ_INT(cairn_session_open(&b, &hdr, pt, sizeof pt, &ptlen,
                                        ct, ctlen), CAIRN_OK);
    CT_ASSERT_EQ_INT(ptlen, 9);
    CT_ASSERT_MEM_EQ(pt, "hello bob", 9);

    /* And the other direction, in the same epoch. */
    CT_ASSERT_EQ_INT(cairn_session_seal(&b, &hdr, ct, sizeof ct, &ctlen,
                                        "hi alice", 8), CAIRN_OK);
    CT_ASSERT_EQ_INT(cairn_session_open(&a, &hdr, pt, sizeof pt, &ptlen,
                                        ct, ctlen), CAIRN_OK);
    CT_ASSERT_MEM_EQ(pt, "hi alice", 8);

    cairn_session_clear(&a);
    cairn_session_clear(&b);
    cairn_identity_clear(&ida);
    cairn_identity_clear(&idb);
}

/* This is the defect the reference implementation had: with a static chain key
 * every message in a chain shares one key. Here the index must advance and the
 * ciphertexts must differ even for identical plaintext. */
CT_TEST(session_chain_key_advances)
{
    cairn_identity ida, idb;
    cairn_session a, b;
    cairn_header h1, h2;
    uint8_t c1[64], c2[64];
    size_t l1 = 0, l2 = 0;

    CT_ASSERT_EQ_INT(cairn_identity_generate(&ida), CAIRN_OK);
    CT_ASSERT_EQ_INT(cairn_identity_generate(&idb), CAIRN_OK);
    CT_ASSERT_EQ_INT(handshake(&a, &b, &ida, &idb), CAIRN_OK);

    CT_ASSERT_EQ_INT(cairn_session_seal(&a, &h1, c1, sizeof c1, &l1, "same", 4), CAIRN_OK);
    CT_ASSERT_EQ_INT(cairn_session_seal(&a, &h2, c2, sizeof c2, &l2, "same", 4), CAIRN_OK);
    CT_ASSERT_EQ_INT(h2.index, h1.index + 1);
    CT_ASSERT(!cairn_memeq(c1, c2, l1));

    /* Both still decrypt, in order. */
    {
        uint8_t pt[64];
        size_t ptlen = 0;
        CT_ASSERT_EQ_INT(cairn_session_open(&b, &h1, pt, sizeof pt, &ptlen, c1, l1), CAIRN_OK);
        CT_ASSERT_EQ_INT(cairn_session_open(&b, &h2, pt, sizeof pt, &ptlen, c2, l2), CAIRN_OK);
    }

    cairn_session_clear(&a);
    cairn_session_clear(&b);
    cairn_identity_clear(&ida);
    cairn_identity_clear(&idb);
}

/* Replaying a message must be refused rather than decrypted twice. */
CT_TEST(session_replay_rejected)
{
    cairn_identity ida, idb;
    cairn_session a, b;
    cairn_header hdr;
    uint8_t ct[128], pt[128];
    size_t ctlen = 0, ptlen = 0;

    CT_ASSERT_EQ_INT(cairn_identity_generate(&ida), CAIRN_OK);
    CT_ASSERT_EQ_INT(cairn_identity_generate(&idb), CAIRN_OK);
    CT_ASSERT_EQ_INT(handshake(&a, &b, &ida, &idb), CAIRN_OK);

    CT_ASSERT_EQ_INT(cairn_session_seal(&a, &hdr, ct, sizeof ct, &ctlen, "once", 4), CAIRN_OK);
    CT_ASSERT_EQ_INT(cairn_session_open(&b, &hdr, pt, sizeof pt, &ptlen, ct, ctlen), CAIRN_OK);
    CT_ASSERT_EQ_INT(cairn_session_open(&b, &hdr, pt, sizeof pt, &ptlen, ct, ctlen),
                     CAIRN_ERR_REPLAY);

    cairn_session_clear(&a);
    cairn_session_clear(&b);
    cairn_identity_clear(&ida);
    cairn_identity_clear(&idb);
}

/* A message with a different ratchet public key than advertised must fail. */
CT_TEST(session_tamper_rejected)
{
    cairn_identity ida, idb;
    cairn_session a, b;
    cairn_header hdr;
    uint8_t ct[128], pt[128];
    size_t ctlen = 0, ptlen = 0;

    CT_ASSERT_EQ_INT(cairn_identity_generate(&ida), CAIRN_OK);
    CT_ASSERT_EQ_INT(cairn_identity_generate(&idb), CAIRN_OK);
    CT_ASSERT_EQ_INT(handshake(&a, &b, &ida, &idb), CAIRN_OK);

    CT_ASSERT_EQ_INT(cairn_session_seal(&a, &hdr, ct, sizeof ct, &ctlen, "data", 4), CAIRN_OK);
    ct[0] ^= 0x01;
    CT_ASSERT_EQ_INT(cairn_session_open(&b, &hdr, pt, sizeof pt, &ptlen, ct, ctlen),
                     CAIRN_ERR_AUTH);

    cairn_session_clear(&a);
    cairn_session_clear(&b);
    cairn_identity_clear(&ida);
    cairn_identity_clear(&idb);
}

/* After enough messages the ratchet must step: the epoch and the sender's
 * ratchet public key both change, which is what a static key can never do. */
CT_TEST(session_ratchet_steps)
{
    cairn_identity ida, idb;
    cairn_session a, b;
    cairn_header hdr;
    cairn_header first;
    uint8_t ct[512], pt[512];
    size_t ctlen = 0, ptlen = 0;
    int i;
    int stepped = 0;

    CT_ASSERT_EQ_INT(cairn_identity_generate(&ida), CAIRN_OK);
    CT_ASSERT_EQ_INT(cairn_identity_generate(&idb), CAIRN_OK);
    CT_ASSERT_EQ_INT(handshake(&a, &b, &ida, &idb), CAIRN_OK);

    CT_ASSERT_EQ_INT(cairn_session_seal(&a, &first, ct, sizeof ct, &ctlen, "m", 1), CAIRN_OK);

    for (i = 0; i < CAIRN_RATCHET_INTERVAL * 2; i++) {
        CT_ASSERT_EQ_INT(cairn_session_seal(&a, &hdr, ct, sizeof ct, &ctlen, "m", 1), CAIRN_OK);
        CT_ASSERT_EQ_INT(cairn_session_open(&b, &hdr, pt, sizeof pt, &ptlen, ct, ctlen),
                         CAIRN_OK);
        if (!cairn_memeq(hdr.dh_pub, first.dh_pub, CAIRN_X25519_BYTES)) stepped = 1;
    }
    CT_ASSERT(stepped);
    CT_ASSERT(hdr.epoch > first.epoch);

    cairn_session_clear(&a);
    cairn_session_clear(&b);
    cairn_identity_clear(&ida);
    cairn_identity_clear(&idb);
}

/* A third party without the identity keys cannot complete the handshake. */
CT_TEST(session_wrong_identity_rejected)
{
    cairn_identity ida, idb, evil;
    cairn_session a, b;
    uint8_t init[CAIRN_HANDSHAKE_INIT_BYTES];
    uint8_t resp[CAIRN_HANDSHAKE_RESP_BYTES];
    cairn_pubkey pk_b, pk_evil;
    uint8_t pt[64];
    cairn_header hdr;
    uint8_t tag[CAIRN_TAG_BYTES];
    size_t ptlen = 0;

    CT_ASSERT_EQ_INT(cairn_identity_generate(&ida), CAIRN_OK);
    CT_ASSERT_EQ_INT(cairn_identity_generate(&idb), CAIRN_OK);
    CT_ASSERT_EQ_INT(cairn_identity_generate(&evil), CAIRN_OK);
    cairn_identity_pubkey(&idb, &pk_b);
    cairn_identity_pubkey(&evil, &pk_evil);

    /* Alice asks for Bob, evil answers with its own keys. */
    CT_ASSERT_EQ_INT(cairn_session_init(&a, &ida, &pk_b, init), CAIRN_OK);
    CT_ASSERT_EQ_INT(cairn_session_respond(&b, &evil, resp, init, sizeof init), CAIRN_OK);
    CT_ASSERT_EQ_INT(cairn_session_finish(&a, resp, sizeof resp), CAIRN_OK);

    CT_ASSERT_EQ_INT(cairn_session_confirm_tag(tag, &a, "confirm"), CAIRN_OK);
    CT_ASSERT_EQ_INT(cairn_session_check_tag(&b, "confirm", tag), CAIRN_ERR_AUTH);

    /* An arbitrary ciphertext from the imposter must not open either. */
    memset(&hdr, 0, sizeof hdr);
    hdr.epoch = 0;
    hdr.index = 0;
    memcpy(hdr.dh_pub, a.send_dh_pub, CAIRN_X25519_BYTES);
    CT_ASSERT(cairn_session_open(&b, &hdr, pt, sizeof pt, &ptlen, "junkjunkjunk", 12)
              != CAIRN_OK);
    (void)pk_evil;

    cairn_session_clear(&a);
    cairn_session_clear(&b);
    cairn_identity_clear(&ida);
    cairn_identity_clear(&idb);
    cairn_identity_clear(&evil);
}

/* Out of order delivery within a chain must still work, up to the limit. */
CT_TEST(session_out_of_order)
{
    cairn_identity ida, idb;
    cairn_session a, b;
    cairn_header h[4];
    uint8_t ct[4][128];
    size_t len[4];
    uint8_t pt[128];
    size_t ptlen = 0;
    int i;

    CT_ASSERT_EQ_INT(cairn_identity_generate(&ida), CAIRN_OK);
    CT_ASSERT_EQ_INT(cairn_identity_generate(&idb), CAIRN_OK);
    CT_ASSERT_EQ_INT(handshake(&a, &b, &ida, &idb), CAIRN_OK);

    for (i = 0; i < 4; i++)
        CT_ASSERT_EQ_INT(cairn_session_seal(&a, &h[i], ct[i], sizeof ct[i], &len[i],
                                            "x", 1), CAIRN_OK);

    /* Deliver 3, 1, 0, 2. */
    CT_ASSERT_EQ_INT(cairn_session_open(&b, &h[3], pt, sizeof pt, &ptlen, ct[3], len[3]), CAIRN_OK);
    CT_ASSERT_EQ_INT(cairn_session_open(&b, &h[1], pt, sizeof pt, &ptlen, ct[1], len[1]), CAIRN_OK);
    CT_ASSERT_EQ_INT(cairn_session_open(&b, &h[0], pt, sizeof pt, &ptlen, ct[0], len[0]), CAIRN_OK);
    CT_ASSERT_EQ_INT(cairn_session_open(&b, &h[2], pt, sizeof pt, &ptlen, ct[2], len[2]), CAIRN_OK);
    /* Replays of the skipped ones must now be refused too. */
    CT_ASSERT_EQ_INT(cairn_session_open(&b, &h[1], pt, sizeof pt, &ptlen, ct[1], len[1]),
                     CAIRN_ERR_REPLAY);

    cairn_session_clear(&a);
    cairn_session_clear(&b);
    cairn_identity_clear(&ida);
    cairn_identity_clear(&idb);
}

CT_TEST(session_args_and_state)
{
    cairn_session a;
    cairn_header hdr;
    uint8_t buf[64];
    uint8_t pt[64];
    size_t len = 0;

    memset(&a, 0, sizeof a);
    /* Sealing before the handshake is a state error, not a crash. */
    CT_ASSERT_EQ_INT(cairn_session_seal(&a, &hdr, buf, sizeof buf, &len, "x", 1),
                     CAIRN_ERR_STATE);
    CT_ASSERT_EQ_INT(cairn_session_open(&a, &hdr, pt, sizeof pt, &len, "x", 1),
                     CAIRN_ERR_STATE);
    CT_ASSERT_EQ_INT(cairn_session_init(NULL, NULL, NULL, NULL), CAIRN_ERR_ARG);
    cairn_session_clear(&a);
}

void ct_reg_session(void)
{
    CT_REG(session_handshake_establishes);
    CT_REG(session_confirm_tag_matches);
    CT_REG(session_message_roundtrip);
    CT_REG(session_chain_key_advances);
    CT_REG(session_replay_rejected);
    CT_REG(session_tamper_rejected);
    CT_REG(session_ratchet_steps);
    CT_REG(session_wrong_identity_rejected);
    CT_REG(session_out_of_order);
    CT_REG(session_args_and_state);
}