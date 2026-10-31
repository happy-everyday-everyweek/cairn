#include "test.h"

#include "cairn/protocol.h"

/* The pairing decision, checked as a table.
 *
 * Every bug found in the facade during development was a branching mistake here,
 * and none of them could be reproduced quickly through a socket. Keeping the
 * decision pure means each case below is a two line test instead of a two second
 * network run, and the cases that used to be wrong are now pinned by name.
 */

static cairn_pair_view view(int state, int has_key, int we_initiate, int key_due,
                            int hello_due)
{
    cairn_pair_view v;
    v.peer_state = state;
    v.has_key = has_key;
    v.we_initiate = we_initiate;
    v.key_due = key_due;
    v.hello_due = hello_due;
    /* Due by default, so a case that does not care about the responder timer does not
     * have to mention it. The tests that do care set it explicitly. */
    v.accept_due = 1;
    return v;
}

/* An empty slot is nobody, and a ready one needs nothing. */
CT_TEST(pair_next_ignores_empty_and_ready)
{
    cairn_pair_view v;

    v = view(CAIRN_ENGINE_EMPTY, 0, 1, 1, 1);
    CT_ASSERT_EQ_INT(cairn_pair_next(&v), CAIRN_PAIR_IDLE);

    v = view(CAIRN_ENGINE_EMPTY, 1, 1, 1, 1);
    CT_ASSERT_EQ_INT(cairn_pair_next(&v), CAIRN_PAIR_IDLE);

    v = view(CAIRN_ENGINE_READY, 1, 1, 1, 1);
    CT_ASSERT_EQ_INT(cairn_pair_next(&v), CAIRN_PAIR_IDLE);
}

/* Without the peer's key the only useful action is sending ours. This is the rule
 * that used to be missing, and its absence deadlocked both devices. */
CT_TEST(pair_next_sends_key_when_key_missing)
{
    cairn_pair_view v;

    v = view(CAIRN_ENGINE_KNOWN, 0, 1, 1, 1);
    CT_ASSERT_EQ_INT(cairn_pair_next(&v), CAIRN_PAIR_SEND_KEY);

    /* Also true when we are not the initiator: the responder still has to publish its
     * key before the initiator can address it. */
    v = view(CAIRN_ENGINE_KNOWN, 0, 0, 1, 1);
    CT_ASSERT_EQ_INT(cairn_pair_next(&v), CAIRN_PAIR_SEND_KEY);
}

/* But not before the retransmit timer is due, so a tight loop does not flood. */
CT_TEST(pair_next_waits_for_key_timer)
{
    cairn_pair_view v;

    v = view(CAIRN_ENGINE_KNOWN, 0, 1, 0, 0);
    CT_ASSERT_EQ_INT(cairn_pair_next(&v), CAIRN_PAIR_IDLE);
}

/* With both keys held, only the initiator sends HELLO, and only on its timer. */
CT_TEST(pair_next_hello_needs_both_keys_and_initiator)
{
    cairn_pair_view v;

    v = view(CAIRN_ENGINE_KNOWN, 1, 1, 0, 1);
    CT_ASSERT_EQ_INT(cairn_pair_next(&v), CAIRN_PAIR_SEND_HELLO);

    /* The responder must not send one as well, or both sides would speak at once. */
    v = view(CAIRN_ENGINE_KNOWN, 1, 0, 0, 1);
    CT_ASSERT_EQ_INT(cairn_pair_next(&v), CAIRN_PAIR_IDLE);

    /* Not due yet. */
    v = view(CAIRN_ENGINE_KNOWN, 1, 1, 0, 0);
    CT_ASSERT_EQ_INT(cairn_pair_next(&v), CAIRN_PAIR_IDLE);
}

/* A handshake already in flight is retransmitted, never restarted and never
 * abandoned. Leaving it silent is what turned one lost datagram into a pairing
 * attempt that could only end in a timeout. */
CT_TEST(pair_next_retransmits_handshake_in_flight)
{
    cairn_pair_view v;

    /* The initiator resends its HELLO on its own timer. */
    v = view(CAIRN_ENGINE_HANDSHAKING, 1, 1, 1, 1);
    CT_ASSERT_EQ_INT(cairn_pair_next(&v), CAIRN_PAIR_SEND_HELLO);

    /* Not due yet. */
    v = view(CAIRN_ENGINE_HANDSHAKING, 1, 1, 1, 0);
    CT_ASSERT_EQ_INT(cairn_pair_next(&v), CAIRN_PAIR_IDLE);

    /* The responder resends its ACCEPT, because the initiator has no way to ask. */
    v = view(CAIRN_ENGINE_HANDSHAKING, 1, 0, 0, 0);
    CT_ASSERT_EQ_INT(cairn_pair_next(&v), CAIRN_PAIR_SEND_ACCEPT);

    v.accept_due = 0;
    CT_ASSERT_EQ_INT(cairn_pair_next(&v), CAIRN_PAIR_IDLE);

    /* A peer we still lack a key for is the exception: publishing our key comes
     * first regardless of the phase. */
    v = view(CAIRN_ENGINE_HANDSHAKING, 0, 0, 1, 1);
    CT_ASSERT_EQ_INT(cairn_pair_next(&v), CAIRN_PAIR_SEND_KEY);
}

/* A failed slot returns to publishing the key rather than staying dead, so one lost
 * datagram does not end the attempt. */
CT_TEST(pair_next_retries_after_failure)
{
    cairn_pair_view v;

    v = view(CAIRN_ENGINE_FAILED, 0, 1, 1, 1);
    CT_ASSERT_EQ_INT(cairn_pair_next(&v), CAIRN_PAIR_SEND_KEY);

    v = view(CAIRN_ENGINE_FAILED, 1, 1, 1, 1);
    CT_ASSERT_EQ_INT(cairn_pair_next(&v), CAIRN_PAIR_IDLE);
}

/* The two devices must never both decide to send HELLO. Given the same pair of ids,
 * exactly one side computes we_initiate true. */
CT_TEST(pair_next_roles_are_complementary)
{
    cairn_pair_view v;

    /* Device a sorts lower, so only a initiates. */
    v = view(CAIRN_ENGINE_KNOWN, 1, 1, 0, 1);
    CT_ASSERT_EQ_INT(cairn_pair_next(&v), CAIRN_PAIR_SEND_HELLO);

    /* Device b sorts higher, so b waits. */
    v = view(CAIRN_ENGINE_KNOWN, 1, 0, 0, 1);
    CT_ASSERT_EQ_INT(cairn_pair_next(&v), CAIRN_PAIR_IDLE);
}

CT_TEST(pair_next_null_is_idle)
{
    CT_ASSERT_EQ_INT(cairn_pair_next(NULL), CAIRN_PAIR_IDLE);
}

void ct_reg_pair_logic(void)
{
    CT_REG(pair_next_ignores_empty_and_ready);
    CT_REG(pair_next_sends_key_when_key_missing);
    CT_REG(pair_next_waits_for_key_timer);
    CT_REG(pair_next_hello_needs_both_keys_and_initiator);
    CT_REG(pair_next_retransmits_handshake_in_flight);
    CT_REG(pair_next_retries_after_failure);
    CT_REG(pair_next_roles_are_complementary);
    CT_REG(pair_next_null_is_idle);
}