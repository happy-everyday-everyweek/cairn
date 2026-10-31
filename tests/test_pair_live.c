#include "test.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "cairn/cairn.h"

/* Two nodes, two real sockets, one process, two threads.
 *
 * This is the test that was missing: the engine tests drive cairn_engine_connect by
 * hand, so they could not notice that the facade never called it; the facade tests run
 * a single node, so they could not notice that two nodes never found each other. Only
 * this file puts two facade instances against each other over the network stack.
 *
 * It needs the host to deliver a UDP datagram from a socket back to another socket on
 * this machine. Most do; some CI images do not. When that is the case the test says so
 * instead of failing, because a red mark there would mean the environment, not the
 * protocol.
 */

static int loopback_delivers(void)
{
    struct sockaddr_in addr;
    socklen_t len = sizeof addr;
    struct pollfd pfd;
    int fd, ok = 0;
    char byte = 'x';

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return 0;

    memset(&addr, 0, sizeof addr);
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    addr.sin_port = 0;
    if (bind(fd, (struct sockaddr *)&addr, sizeof addr) != 0) {
        close(fd);
        return 0;
    }
    if (getsockname(fd, (struct sockaddr *)&addr, &len) != 0) {
        close(fd);
        return 0;
    }

    if (sendto(fd, &byte, 1, 0, (struct sockaddr *)&addr, sizeof addr) == 1) {
        pfd.fd = fd;
        pfd.events = POLLIN;
        if (poll(&pfd, 1, 500) == 1) {
            char got = 0;
            if (recv(fd, &got, 1, 0) == 1 && got == 'x') ok = 1;
        }
    }

    close(fd);
    return ok;
}

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

    if (!loopback_delivers())
        CT_SKIP("this host does not deliver UDP to another socket on loopback");

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
    a.timeout_ms = 6000;
    b.code = "424242";
    b.timeout_ms = 6000;

    pthread_create(&ta, NULL, pair_thread, &a);
    pthread_create(&tb, NULL, pair_thread, &b);
    pthread_join(ta, NULL);
    pthread_join(tb, NULL);

    CT_ASSERT_EQ_INT(a.result, CAIRN_OK);
    CT_ASSERT_EQ_INT(b.result, CAIRN_OK);
    CT_ASSERT_EQ_INT(cairn_is_ready(a.node), 1);
    CT_ASSERT_EQ_INT(cairn_is_ready(b.node), 1);

    /* And once paired, a message must arrive. */
    CT_ASSERT_EQ_INT(cairn_send(a.node, "ping", 4), CAIRN_OK);
    {
        int waited;
        for (waited = 0; waited < 80 && b.messages == 0; waited++)
            cairn_poll(b.node, 25);
    }
    CT_ASSERT_EQ_INT(b.messages, 1);
    CT_ASSERT_MEM_EQ(b.last, "ping", 4);

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

    if (!loopback_delivers())
        CT_SKIP("this host does not deliver UDP to another socket on loopback");

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
