#include "test.h"

#include <string.h>

#include "cairn/cairn.h"
#include "cairn/discovery.h"

/* The facade is what an application actually calls, so it needs its own tests. The
 * previous gap is worth naming: test_pair.c proved the engine rejects a wrong code,
 * but it drove cairn_engine_connect itself, so it could not notice that the facade
 * never called it at all. These tests call only the public facade, on real sockets,
 * which is the layer where that kind of mistake lives.
 */

typedef struct {
    int messages;
    int paired;
    size_t last_len;
    char last[256];
} app;

static void on_message(void *user, const uint8_t peer[CAIRN_ID_BYTES],
                       const void *data, size_t len)
{
    app *a = (app *)user;
    (void)peer;
    a->messages++;
    a->last_len = len < sizeof a->last ? len : sizeof a->last - 1;
    memcpy(a->last, data, a->last_len);
    a->last[a->last_len] = '\0';
}

static void on_ready(void *user, const uint8_t peer[CAIRN_ID_BYTES])
{
    app *a = (app *)user;
    (void)peer;
    a->paired = 1;
}

/* Opening a node must give a usable handle and a readable fingerprint. */
CT_TEST(facade_open_close)
{
    cairn_io io;
    cairn_node *n;
    char fp[18];

    memset(&io, 0, sizeof io);
    io.on_message = on_message;

    n = cairn_open("test", &io);
    CT_ASSERT(n != NULL);
    CT_ASSERT_EQ_INT(cairn_fingerprint(n, fp), CAIRN_OK);
    /* Six groups of two hex digits. */
    CT_ASSERT_EQ_INT((int)strlen(fp), 17);
    CT_ASSERT_EQ_INT(fp[2], ':');

    cairn_close(n);
    cairn_close(NULL);
}

/* Sending before pairing must be refused rather than crash or leak plaintext. */
CT_TEST(facade_send_requires_pairing)
{
    cairn_io io;
    cairn_node *n;

    memset(&io, 0, sizeof io);
    n = cairn_open("test", &io);
    CT_ASSERT(n != NULL);

    CT_ASSERT_EQ_INT(cairn_send(n, "x", 1), CAIRN_ERR_STATE);
    CT_ASSERT_EQ_INT(cairn_send(n, "x", 1), CAIRN_ERR_STATE);
    CT_ASSERT_EQ_INT(cairn_is_ready(n), 0);

    cairn_close(n);
}

/* A code must be four to twelve digits. Anything else is refused before the network
 * is touched, so a UI bug cannot turn into a weaker pairing. */
CT_TEST(facade_code_validation)
{
    cairn_io io;
    cairn_node *n;

    memset(&io, 0, sizeof io);
    n = cairn_open("test", &io);
    CT_ASSERT(n != NULL);

    CT_ASSERT_EQ_INT(cairn_pair_wait(n, "123", 1), CAIRN_ERR_ARG);
    CT_ASSERT_EQ_INT(cairn_pair_wait(n, "1234567890123", 1), CAIRN_ERR_ARG);
    CT_ASSERT_EQ_INT(cairn_pair_wait(n, "12a456", 1), CAIRN_ERR_ARG);
    CT_ASSERT_EQ_INT(cairn_pair_wait(n, "", 1), CAIRN_ERR_ARG);
    CT_ASSERT_EQ_INT(cairn_pair_wait(NULL, "123456", 1), CAIRN_ERR_ARG);
    CT_ASSERT_EQ_INT(cairn_pair_join(n, "12 45", 1), CAIRN_ERR_ARG);

    cairn_close(n);
}

/* A well formed code with nobody else around must time out rather than hang or claim
 * success. This is the assertion that would have caught the missing
 * cairn_engine_connect: pairing used to return success as soon as it was called. */
CT_TEST(facade_pair_times_out_alone)
{
    cairn_io io;
    cairn_node *n;
    int rc;

    memset(&io, 0, sizeof io);
    n = cairn_open("lonely", &io);
    CT_ASSERT(n != NULL);

    rc = cairn_pair_wait(n, "123456", 600);
    CT_ASSERT_EQ_INT(rc, CAIRN_ERR_TIMEOUT);
    CT_ASSERT_EQ_INT(cairn_is_ready(n), 0);

    cairn_close(n);
}

/* The beacon a node publishes must name the port that node actually listens on. A zero
 * here means a peer that answers the beacon sends to port zero, which was the second
 * defect: the socket bound an ephemeral port while the beacon still carried the zero
 * passed to cairn_open. */
CT_TEST(facade_beacon_carries_bound_port)
{
    cairn_io io;
    cairn_node *n;
    const void *data = NULL;
    size_t len = 0;
    cairn_beacon b;

    memset(&io, 0, sizeof io);
    n = cairn_open("listener", &io);
    CT_ASSERT(n != NULL);

    CT_ASSERT_EQ_INT(cairn_beacon_payload(n, &data, &len), CAIRN_OK);
    CT_ASSERT(data != NULL);
    CT_ASSERT(len > 0);

    CT_ASSERT_EQ_INT(cairn_beacon_decode(&b, data, (size_t)len), CAIRN_OK);
    CT_ASSERT(b.port != 0);

    cairn_close(n);
}

/* Relaying a datagram that is not ours must be reported, not crash. */
CT_TEST(facade_rejects_garbage)
{
    cairn_io io;
    cairn_node *n;

    memset(&io, 0, sizeof io);
    n = cairn_open("test", &io);
    CT_ASSERT(n != NULL);

    CT_ASSERT(cairn_on_datagram(n, "not a frame at all", 18) != CAIRN_OK);
    CT_ASSERT(cairn_on_beacon(n, "not a beacon", 12) != CAIRN_OK);
    CT_ASSERT_EQ_INT(cairn_on_datagram(NULL, "x", 1), CAIRN_ERR_ARG);

    cairn_close(n);
}

void ct_reg_facade(void)
{
    CT_REG(facade_open_close);
    CT_REG(facade_send_requires_pairing);
    CT_REG(facade_code_validation);
    CT_REG(facade_pair_times_out_alone);
    CT_REG(facade_beacon_carries_bound_port);
    CT_REG(facade_rejects_garbage);
}