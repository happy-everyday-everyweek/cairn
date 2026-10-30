#include "test.h"

#include <pthread.h>
#include <string.h>

#include "cairn/cairn.h"

/* Two real nodes, two real sockets, one process, two threads.
 *
 * This is the test that was missing. test_pair.c drives the engine by hand, so it can
 * prove the code binding works but cannot notice that the facade never starts a
 * handshake. test_facade.c checks the facade's contract but only ever runs one node.
 * Only this file puts two facade instances against each other over the network stack,
 * which is the arrangement an application actually uses.
 *
 * A thread per node gets both sides pumping at once. The facade is single threaded by
 * design and each side owns its own node, so this is the same arrangement a two
 * process run would have.
 */

typedef struct {
    cairn_node *node;
    const char *code;
    uint32_t timeout_ms;
    int result;
    int messages;
    char last[128];
} peer;

static void on_message(void *user, const uint8_t id[CAIRN_ID_BYTES],
                       const void *data, size_t len)
{
    peer *p = (peer *)user;
    size_t n = len < sizeof p->last - 1 ? len : sizeof p->last - 1;
    (void)id;
    p->messages++;
    memcpy(p->last, data, n);
    p->last[n] = '\0';
}

static void *pair_thread(void *arg)
{
    peer *p = (peer *)arg;
    p->result = cairn_pair_wait(p->node, p->code, p->timeout_ms);
    return NULL;
}

/* Both sides must reach a usable channel with the same code. If this fails, pairing
 * does not work at all, whatever the engine tests say. */
CT_TEST(two_nodes_pair_with_same_code)
{
    cairn_io io;
    peer a, b;
    pthread_t ta, tb;

    memset(&io, 0, sizeof io);
    io.on_message = on_message;

    memset(&a, 0, sizeof a);
    memset(&b, 0, sizeof b);

    io.user = &a;
    a.node = cairn_open("alice", &io);
    io.user = &b;
    b.node = cairn_open("bob", &io);
    CT_ASSERT(a.node != NULL);
    CT_ASSERT(b.node != NULL);

    a.code = "424242";
    a.timeout_ms = 3000;
    b.code = "424242";
    b.timeout_ms = 3000;

    pthread_create(&ta, NULL, pair_thread, &a);
    pthread_create(&tb, NULL, pair_thread, &b);
    pthread_join(ta, NULL);
    pthread_join(tb, NULL);

    CT_ASSERT_EQ_INT(a.result, CAIRN_OK);
    CT_ASSERT_EQ_INT(b.result, CAIRN_OK);
    CT_ASSERT_EQ_INT(cairn_is_ready(a.node), 1);
    CT_ASSERT_EQ_INT(cairn_is_ready(b.node), 1);

    cairn_close(a.node);
    cairn_close(b.node);
}

/* With different codes the handshake must fail on both sides. This is the property
 * that makes the code meaningful, checked at the layer an application uses. */
CT_TEST(two_nodes_reject_different_codes)
{
    cairn_io io;
    peer a, b;
    pthread_t ta, tb;

    memset(&io, 0, sizeof io);
    io.on_message = on_message;

    memset(&a, 0, sizeof a);
    memset(&b, 0, sizeof b);

    io.user = &a;
    a.node = cairn_open("alice", &io);
    io.user = &b;
    b.node = cairn_open("bob", &io);
    CT_ASSERT(a.node != NULL);
    CT_ASSERT(b.node != NULL);

    a.code = "111111";
    a.timeout_ms = 2500;
    b.code = "999999";
    b.timeout_ms = 2500;

    pthread_create(&ta, NULL, pair_thread, &a);
    pthread_create(&tb, NULL, pair_thread, &b);
    pthread_join(ta, NULL);
    pthread_join(tb, NULL);

    /* Neither side may claim success. */
    CT_ASSERT(a.result != CAIRN_OK);
    CT_ASSERT(b.result != CAIRN_OK);
    CT_ASSERT_EQ_INT(cairn_is_ready(a.node), 0);
    CT_ASSERT_EQ_INT(cairn_is_ready(b.node), 0);

    cairn_close(a.node);
    cairn_close(b.node);
}

void ct_reg_pair_live(void)
{
    CT_REG(two_nodes_pair_with_same_code);
    CT_REG(two_nodes_reject_different_codes);
}