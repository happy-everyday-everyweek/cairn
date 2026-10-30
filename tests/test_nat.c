#include "test.h"

#include <string.h>

#include "cairn/nat.h"

static void put_u16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)v;
}

/* Builds a binding success response with an XOR-MAPPED-ADDRESS attribute, laid
 * out by hand from RFC 5389 section 15.2. The test must not use the code under
 * test to produce its own input. */
static size_t build_xor_response(uint8_t *out, const uint8_t tid[12],
                                 uint32_t ip, uint16_t port)
{
    size_t o = 20;

    put_u16(out + 0, CAIRN_STUN_BINDING_SUCCESS);
    put_u16(out + 2, 12); /* attribute area: 4 header + 8 body */
    out[4] = 0x21;
    out[5] = 0x12;
    out[6] = 0xa4;
    out[7] = 0x42;
    memcpy(out + 8, tid, 12);

    put_u16(out + o, CAIRN_STUN_ATTR_XOR_MAPPED_ADDRESS);
    put_u16(out + o + 2, 8);
    out[o + 4] = 0;    /* reserved */
    out[o + 5] = 0x01; /* family: IPv4 */
    put_u16(out + o + 6, (uint16_t)(port ^ 0x2112));
    {
        uint32_t xored = ip ^ CAIRN_STUN_MAGIC;
        out[o + 8] = (uint8_t)(xored >> 24);
        out[o + 9] = (uint8_t)(xored >> 16);
        out[o + 10] = (uint8_t)(xored >> 8);
        out[o + 11] = (uint8_t)xored;
    }
    return o + 12;
}

/* And a plain MAPPED-ADDRESS variant, for the fallback path. */
static size_t build_plain_response(uint8_t *out, const uint8_t tid[12],
                                   uint32_t ip, uint16_t port)
{
    size_t o = 20;

    out[0] = 0x01;
    out[1] = 0x01;
    put_u16(out + 2, 12);
    out[4] = 0x21;
    out[5] = 0x12;
    out[6] = 0xa4;
    out[7] = 0x42;
    memcpy(out + 8, tid, 12);

    put_u16(out + o, CAIRN_STUN_ATTR_MAPPED_ADDRESS);
    put_u16(out + o + 2, 8);
    out[o + 4] = 0;
    out[o + 5] = 0x01;
    put_u16(out + o + 6, port);
    out[o + 8] = (uint8_t)(ip >> 24);
    out[o + 9] = (uint8_t)(ip >> 16);
    out[o + 10] = (uint8_t)(ip >> 8);
    out[o + 11] = (uint8_t)ip;
    return o + 12;
}

CT_TEST(stun_request_layout)
{
    uint8_t buf[CAIRN_STUN_MAX_BYTES];
    size_t len = 0;
    uint8_t tid[12];

    memset(tid, 0x3c, sizeof tid);
    CT_ASSERT_EQ_INT(cairn_stun_build_request(buf, sizeof buf, &len, tid), CAIRN_OK);
    CT_ASSERT_EQ_INT(len, CAIRN_STUN_HEADER_BYTES);

    /* Message type 0x0001, length 0, magic cookie, then the transaction id. */
    CT_ASSERT_EQ_INT(buf[0], 0x00);
    CT_ASSERT_EQ_INT(buf[1], 0x01);
    CT_ASSERT_EQ_INT(buf[2], 0x00);
    CT_ASSERT_EQ_INT(buf[3], 0x00);
    CT_ASSERT_EQ_INT(buf[4], 0x21);
    CT_ASSERT_EQ_INT(buf[5], 0x12);
    CT_ASSERT_EQ_INT(buf[6], 0xa4);
    CT_ASSERT_EQ_INT(buf[7], 0x42);
    CT_ASSERT_MEM_EQ(buf + 8, tid, 12);
}

/* A NULL transaction id means: make one up, and it must not be all zero. */
CT_TEST(stun_request_random_tid)
{
    uint8_t buf[CAIRN_STUN_MAX_BYTES];
    uint8_t again[CAIRN_STUN_MAX_BYTES];
    size_t len = 0, len2 = 0;
    static const uint8_t zero[12] = {0};

    CT_ASSERT_EQ_INT(cairn_stun_build_request(buf, sizeof buf, &len, NULL), CAIRN_OK);
    CT_ASSERT(!cairn_memeq(buf + 8, zero, 12));
    CT_ASSERT_EQ_INT(cairn_stun_build_request(again, sizeof again, &len2, NULL), CAIRN_OK);
    CT_ASSERT(!cairn_memeq(buf + 8, again + 8, 12));
}

CT_TEST(stun_request_short_buffer)
{
    uint8_t buf[8];
    size_t len = 0;
    uint8_t tid[12];

    memset(tid, 0, sizeof tid);
    CT_ASSERT_EQ_INT(cairn_stun_build_request(buf, sizeof buf, &len, tid), CAIRN_ERR_BUFFER);
}

CT_TEST(stun_parse_xor_mapped)
{
    uint8_t buf[128];
    uint8_t tid[12];
    uint8_t got_tid[12];
    cairn_endpoint ep;
    size_t len;

    memset(tid, 0x77, sizeof tid);
    len = build_xor_response(buf, tid, 0x0a000105u, 54321);
    CT_ASSERT_EQ_INT(cairn_stun_parse_response(got_tid, &ep, buf, len), CAIRN_OK);
    CT_ASSERT_MEM_EQ(got_tid, tid, 12);
    CT_ASSERT_EQ_INT(ep.ip, 0x0a000105u);
    CT_ASSERT_EQ_INT(ep.port, 54321);
}

/* The plain attribute is the fallback when a server omits the XOR one. */
CT_TEST(stun_parse_plain_mapped)
{
    uint8_t buf[128];
    uint8_t tid[12];
    uint8_t got_tid[12];
    cairn_endpoint ep;
    size_t len;

    memset(tid, 0x88, sizeof tid);
    len = build_plain_response(buf, tid, 0xc0a80101u, 1234);
    CT_ASSERT_EQ_INT(cairn_stun_parse_response(got_tid, &ep, buf, len), CAIRN_OK);
    CT_ASSERT_EQ_INT(ep.ip, 0xc0a80101u);
    CT_ASSERT_EQ_INT(ep.port, 1234);
}

/* A response with the wrong cookie, a bad length, or truncation must be refused. */
CT_TEST(stun_parse_rejects_garbage)
{
    uint8_t buf[128];
    uint8_t tid[12];
    uint8_t got_tid[12];
    cairn_endpoint ep;
    size_t len;
    size_t cut;

    memset(tid, 0x99, sizeof tid);
    len = build_xor_response(buf, tid, 0x01020304u, 999);

    for (cut = 0; cut < len; cut++)
        CT_ASSERT(cairn_stun_parse_response(got_tid, &ep, buf, cut) != CAIRN_OK);

    /* Wrong magic cookie. */
    len = build_xor_response(buf, tid, 0x01020304u, 999);
    buf[4] = 0xde;
    CT_ASSERT(cairn_stun_parse_response(got_tid, &ep, buf, len) != CAIRN_OK);

    /* An error response is not a success. */
    len = build_xor_response(buf, tid, 0x01020304u, 999);
    buf[0] = 0x01;
    buf[1] = 0x11;
    CT_ASSERT(cairn_stun_parse_response(got_tid, &ep, buf, len) != CAIRN_OK);

    /* An attribute length that runs past the buffer. */
    len = build_xor_response(buf, tid, 0x01020304u, 999);
    buf[2] = 0x7f;
    buf[3] = 0xff;
    CT_ASSERT(cairn_stun_parse_response(got_tid, &ep, buf, len) != CAIRN_OK);
}

CT_TEST(nat_begin_and_poll)
{
    cairn_nat n;
    cairn_endpoint local = {0x0a000102u, 40000};
    cairn_endpoint external = {0x5db8d822u, 62000};
    cairn_endpoint peer = {0x5db8d8ccu, 62001};
    int send = 0;

    memset(&n, 0, sizeof n);
    CT_ASSERT_EQ_INT(cairn_nat_begin(&n, local, external, peer, 1000), CAIRN_OK);
    CT_ASSERT_EQ_INT(n.state, CAIRN_NAT_PUNCHING);
    CT_ASSERT_EQ_INT(n.peer.ip, peer.ip);

    /* The first poll after begin is due immediately. */
    CT_ASSERT_EQ_INT(cairn_nat_poll(&n, 1000, &send), CAIRN_OK);
    CT_ASSERT_EQ_INT(send, 1);
    CT_ASSERT_EQ_INT(n.attempts, 1);

    /* A poll before the interval elapses must not send again. */
    CT_ASSERT_EQ_INT(cairn_nat_poll(&n, 1050, &send), CAIRN_OK);
    CT_ASSERT_EQ_INT(send, 0);
    CT_ASSERT_EQ_INT(n.attempts, 1);

    CT_ASSERT_EQ_INT(cairn_nat_poll(&n, 1000 + n.punch_interval_ms, &send), CAIRN_OK);
    CT_ASSERT_EQ_INT(send, 1);
    CT_ASSERT_EQ_INT(n.attempts, 2);
}

/* A packet from the peer's exact address proves the hole is open. */
CT_TEST(nat_packet_confirms)
{
    cairn_nat n;
    cairn_endpoint local = {0x0a000102u, 40000};
    cairn_endpoint external = {0x5db8d822u, 62000};
    cairn_endpoint peer = {0x5db8d8ccu, 62001};
    cairn_endpoint other = {0x5db8d8ccu, 62002};

    memset(&n, 0, sizeof n);
    CT_ASSERT_EQ_INT(cairn_nat_begin(&n, local, external, peer, 0), CAIRN_OK);

    /* A packet from a different port is not the peer. */
    CT_ASSERT_EQ_INT(cairn_nat_on_packet(&n, other, 100), CAIRN_ERR_NOT_FOUND);
    CT_ASSERT_EQ_INT(n.state, CAIRN_NAT_PUNCHING);

    CT_ASSERT_EQ_INT(cairn_nat_on_packet(&n, peer, 200), CAIRN_OK);
    CT_ASSERT_EQ_INT(n.state, CAIRN_NAT_CONNECTED);
}

/* Punching must give up after the timeout and fall back to a relay. */
CT_TEST(nat_times_out_then_relays)
{
    cairn_nat n;
    cairn_endpoint local = {0x0a000102u, 40000};
    cairn_endpoint external = {0x5db8d822u, 62000};
    cairn_endpoint peer = {0x5db8d8ccu, 62001};
    int send = 0;

    memset(&n, 0, sizeof n);
    CT_ASSERT_EQ_INT(cairn_nat_begin(&n, local, external, peer, 0), CAIRN_OK);

    CT_ASSERT_EQ_INT(cairn_nat_poll(&n, n.timeout_ms + 1, &send), CAIRN_OK);
    CT_ASSERT_EQ_INT(n.state, CAIRN_NAT_FAILED);

    CT_ASSERT_EQ_INT(cairn_nat_fallback_relay(&n), CAIRN_OK);
    CT_ASSERT_EQ_INT(n.state, CAIRN_NAT_RELAYING);
    /* Once relaying, polling must not ask for punch packets. */
    CT_ASSERT_EQ_INT(cairn_nat_poll(&n, n.timeout_ms + 5000, &send), CAIRN_OK);
    CT_ASSERT_EQ_INT(send, 0);
}

/* Learning the external address moves the state on without resetting attempts. */
CT_TEST(nat_set_external)
{
    cairn_nat n;
    cairn_endpoint local = {0x0a000102u, 40000};
    cairn_endpoint external = {0, 0};
    cairn_endpoint learned = {0x5db8d822u, 62000};
    cairn_endpoint peer = {0x5db8d8ccu, 62001};
    int send = 0;

    memset(&n, 0, sizeof n);
    CT_ASSERT_EQ_INT(cairn_nat_begin(&n, local, external, peer, 0), CAIRN_OK);
    /* No external address yet, so nothing can be punched. */
    CT_ASSERT_EQ_INT(cairn_nat_poll(&n, 0, &send), CAIRN_OK);
    CT_ASSERT_EQ_INT(send, 0);
    CT_ASSERT_EQ_INT(n.state, CAIRN_NAT_DISCOVERING);

    CT_ASSERT_EQ_INT(cairn_nat_set_external(&n, learned, 500), CAIRN_OK);
    CT_ASSERT_EQ_INT(n.state, CAIRN_NAT_PUNCHING);
    CT_ASSERT_EQ_INT(n.external.port, learned.port);
    CT_ASSERT_EQ_INT(cairn_nat_poll(&n, 500, &send), CAIRN_OK);
    CT_ASSERT_EQ_INT(send, 1);
}

/* A connected session must stay connected when a packet arrives, not regress. */
CT_TEST(nat_connected_is_sticky)
{
    cairn_nat n;
    cairn_endpoint local = {0x0a000102u, 40000};
    cairn_endpoint external = {0x5db8d822u, 62000};
    cairn_endpoint peer = {0x5db8d8ccu, 62001};
    int send = 0;

    memset(&n, 0, sizeof n);
    CT_ASSERT_EQ_INT(cairn_nat_begin(&n, local, external, peer, 0), CAIRN_OK);
    CT_ASSERT_EQ_INT(cairn_nat_on_packet(&n, peer, 10), CAIRN_OK);
    CT_ASSERT_EQ_INT(cairn_nat_on_packet(&n, peer, 20), CAIRN_OK);
    CT_ASSERT_EQ_INT(n.state, CAIRN_NAT_CONNECTED);

    CT_ASSERT_EQ_INT(cairn_nat_poll(&n, n.timeout_ms + 1000, &send), CAIRN_OK);
    CT_ASSERT_EQ_INT(n.state, CAIRN_NAT_CONNECTED);
    CT_ASSERT_EQ_INT(send, 0);
}

CT_TEST(nat_state_names)
{
    CT_ASSERT(cairn_nat_state_name(CAIRN_NAT_IDLE) != NULL);
    CT_ASSERT(cairn_nat_state_name(CAIRN_NAT_PUNCHING) != NULL);
    CT_ASSERT(cairn_nat_state_name(CAIRN_NAT_CONNECTED) != NULL);
    CT_ASSERT(cairn_nat_state_name(CAIRN_NAT_FAILED) != NULL);
    CT_ASSERT(cairn_nat_state_name(CAIRN_NAT_RELAYING) != NULL);
    CT_ASSERT(cairn_nat_state_name(CAIRN_NAT_DISCOVERING) != NULL);
}

CT_TEST(nat_args_rejected)
{
    cairn_endpoint zero = {0, 0};

    CT_ASSERT_EQ_INT(cairn_nat_begin(NULL, zero, zero, zero, 0), CAIRN_ERR_ARG);
}

void ct_reg_nat(void)
{
    CT_REG(stun_request_layout);
    CT_REG(stun_request_random_tid);
    CT_REG(stun_request_short_buffer);
    CT_REG(stun_parse_xor_mapped);
    CT_REG(stun_parse_plain_mapped);
    CT_REG(stun_parse_rejects_garbage);
    CT_REG(nat_begin_and_poll);
    CT_REG(nat_packet_confirms);
    CT_REG(nat_times_out_then_relays);
    CT_REG(nat_set_external);
    CT_REG(nat_connected_is_sticky);
    CT_REG(nat_state_names);
    CT_REG(nat_args_rejected);
}