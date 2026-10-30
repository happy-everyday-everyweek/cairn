#include "test.h"

#include <string.h>

#include "cairn/crypto.h"
#include "cairn/identity.h"
#include "cairn/protocol.h"

/* The engine driven by hand, with no sockets, so the pairing code can be tested
 * deterministically. The facade in api.c adds a socket and blocking waits on top of
 * exactly this sequence; if the code binding is wrong here it is wrong there too, and
 * this test says so in milliseconds instead of seconds. */

typedef struct {
    cairn_engine engine;
    cairn_identity id;
    cairn_pubkey pub;
} endpoint;

static int setup(endpoint *e, const char *name, const char *code)
{
    if (cairn_identity_generate(&e->id) != CAIRN_OK) return -1;
    if (cairn_identity_pubkey(&e->id, &e->pub) != CAIRN_OK) return -1;
    if (cairn_engine_init(&e->engine, &e->id, name, 0) != CAIRN_OK) return -1;
    if (code != NULL && cairn_engine_set_code(&e->engine, code) != CAIRN_OK) return -1;
    return 0;
}

static void teardown(endpoint *e)
{
    cairn_engine_clear(&e->engine);
    cairn_identity_clear(&e->id);
}

/* Moves one frame from one side to the other, exactly as a transport would. */
static int move(cairn_engine_outbox *out, cairn_engine *to, cairn_engine_outbox *reply)
{
    cairn_frame f;
    size_t used = 0;

    if (out->len == 0) return CAIRN_OK;
    if (cairn_frame_decode(&f, &used, out->buf, out->len) != CAIRN_OK)
        return CAIRN_ERR_FORMAT;

    memset(reply, 0, sizeof *reply);
    return cairn_engine_on_frame(to, &f, 0, reply);
}

/* Runs the three step handshake. Returns zero when both sides reached READY, or a
 * non zero step number at the point it stopped. */
static int handshake(endpoint *a, endpoint *b)
{
    cairn_engine_outbox out, reply;

    if (cairn_engine_add_peer(&a->engine, &b->pub, "b") != CAIRN_OK) return 1;
    if (cairn_engine_add_peer(&b->engine, &a->pub, "a") != CAIRN_OK) return 2;

    memset(&out, 0, sizeof out);
    if (cairn_engine_connect(&a->engine, b->pub.id, 0, &out) != CAIRN_OK) return 3;

    /* HELLO to bob. */
    if (move(&out, &b->engine, &reply) != CAIRN_OK) return 4;

    /* ACCEPT back to alice, which verifies the responder's tag. */
    memset(&out, 0, sizeof out);
    if (move(&reply, &a->engine, &out) != CAIRN_OK) return 5;

    /* ACK to bob, which verifies the initiator's tag. */
    memset(&reply, 0, sizeof reply);
    if (move(&out, &b->engine, &reply) != CAIRN_OK) return 6;

    return 0;
}

static int ready(const endpoint *e)
{
    int i;
    for (i = 0; i < CAIRN_NODE_MAX_SESSIONS; i++)
        if (e->engine.peers[i].state == CAIRN_ENGINE_READY) return 1;
    return 0;
}

/* The same code on both sides must connect. This is the baseline: without it the
 * negative tests below would pass for the wrong reason. */
CT_TEST(pair_same_code_connects)
{
    static endpoint a, b;

    CT_ASSERT_EQ_INT(setup(&a, "alice", "123456"), 0);
    CT_ASSERT_EQ_INT(setup(&b, "bob", "123456"), 0);
    CT_ASSERT_EQ_INT(handshake(&a, &b), 0);
    CT_ASSERT(ready(&a));
    CT_ASSERT(ready(&b));

    teardown(&a);
    teardown(&b);
}

/* A different code must fail at the first tag check, which is the ACCEPT the
 * responder sends back. That is the property the whole pairing design rests on. */
CT_TEST(pair_different_code_rejected)
{
    static endpoint a, b;

    CT_ASSERT_EQ_INT(setup(&a, "alice", "123456"), 0);
    CT_ASSERT_EQ_INT(setup(&b, "bob", "654321"), 0);

    /* The handshake must not complete. */
    CT_ASSERT(handshake(&a, &b) != 0);
    CT_ASSERT(!ready(&a));
    CT_ASSERT(!ready(&b));

    teardown(&a);
    teardown(&b);
}

/* One side coded and the other not must also fail, so an application cannot
 * accidentally pair a coded device with an uncoded one. */
CT_TEST(pair_one_sided_code_rejected)
{
    static endpoint a, b;

    CT_ASSERT_EQ_INT(setup(&a, "alice", "123456"), 0);
    CT_ASSERT_EQ_INT(setup(&b, "bob", NULL), 0);

    CT_ASSERT(handshake(&a, &b) != 0);
    CT_ASSERT(!ready(&a));

    teardown(&a);
    teardown(&b);
}

/* Clearing the code returns the engine to the uncoded behaviour. */
CT_TEST(pair_code_can_be_cleared)
{
    static endpoint a, b;

    CT_ASSERT_EQ_INT(setup(&a, "alice", "1111"), 0);
    CT_ASSERT_EQ_INT(setup(&b, "bob", "1111"), 0);
    CT_ASSERT_EQ_INT(cairn_engine_set_code(&a.engine, NULL), CAIRN_OK);
    CT_ASSERT_EQ_INT(cairn_engine_set_code(&b.engine, NULL), CAIRN_OK);

    CT_ASSERT_EQ_INT(handshake(&a, &b), 0);
    CT_ASSERT(ready(&a));
    CT_ASSERT(ready(&b));

    teardown(&a);
    teardown(&b);
}

/* A code longer than the field must be refused rather than truncated, because a
 * truncated code would silently weaken pairing. */
CT_TEST(pair_code_too_long_rejected)
{
    static endpoint a;

    CT_ASSERT_EQ_INT(setup(&a, "alice", NULL), 0);
    CT_ASSERT_EQ_INT(cairn_engine_set_code(&a.engine, "1234567890123"), CAIRN_ERR_ARG);
    teardown(&a);
}

void ct_reg_pair(void)
{
    CT_REG(pair_same_code_connects);
    CT_REG(pair_different_code_rejected);
    CT_REG(pair_one_sided_code_rejected);
    CT_REG(pair_code_can_be_cleared);
    CT_REG(pair_code_too_long_rejected);
}