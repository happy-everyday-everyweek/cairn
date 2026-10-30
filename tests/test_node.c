#include "test.h"

#include <string.h>

#include "cairn/node.h"

/* Two nodes, both initialised. This is the in-memory loopback the node is
 * designed around: no sockets, no threads, just frames moved by hand. */
typedef struct {
    cairn_node a;
    cairn_node b;
    cairn_identity ida;
    cairn_identity idb;
    cairn_pubkey pka;
    cairn_pubkey pkb;
} pair;

static int pair_setup(pair *p)
{
    if (cairn_identity_generate(&p->ida) != CAIRN_OK) return -1;
    if (cairn_identity_generate(&p->idb) != CAIRN_OK) return -1;
    if (cairn_identity_pubkey(&p->ida, &p->pka) != CAIRN_OK) return -1;
    if (cairn_identity_pubkey(&p->idb, &p->pkb) != CAIRN_OK) return -1;
    if (cairn_node_init(&p->a, &p->ida, "alice", 9101) != CAIRN_OK) return -1;
    if (cairn_node_init(&p->b, &p->idb, "bob", 9102) != CAIRN_OK) return -1;
    /* Each side registers the other's public key, the way a stored paired device
     * would be loaded at startup. */
    if (cairn_node_add_peer(&p->a, &p->pkb, "bob") != CAIRN_OK) return -1;
    if (cairn_node_add_peer(&p->b, &p->pka, "alice") != CAIRN_OK) return -1;
    return 0;
}

static void pair_teardown(pair *p)
{
    cairn_node_clear(&p->a);
    cairn_node_clear(&p->b);
    cairn_identity_clear(&p->ida);
    cairn_identity_clear(&p->idb);
}

/* Delivers one outbox through the wire format, exactly as a transport would. */
static int deliver(cairn_node *dst, const cairn_outbox *box, uint32_t now_ms,
                   cairn_outbox *reply)
{
    cairn_frame f;
    size_t used = 0;
    int rc;

    if (box->len == 0) return CAIRN_OK;
    rc = cairn_frame_decode(&f, &used, box->buf, box->len);
    if (rc != CAIRN_OK) return rc;
    return cairn_node_on_frame(dst, &f, now_ms, reply);
}

/* Runs the whole handshake and leaves both sides ready. */
static int complete_handshake(pair *p)
{
    cairn_outbox out, reply;

    memset(&out, 0, sizeof out);
    if (cairn_node_connect(&p->a, p->idb.id, 1000, &out) != CAIRN_OK) return -1;

    memset(&reply, 0, sizeof reply);
    if (deliver(&p->b, &out, 1000, &reply) != CAIRN_OK) return -1;

    memset(&out, 0, sizeof out);
    if (deliver(&p->a, &reply, 1001, &out) != CAIRN_OK) return -1;

    memset(&reply, 0, sizeof reply);
    if (deliver(&p->b, &out, 1002, &reply) != CAIRN_OK) return -1;

    return 0;
}

/* Both nodes must learn each other from beacons alone. */
CT_TEST(node_beacons_cross_discover)
{
    pair p;
    uint8_t buf[CAIRN_BEACON_MAX];
    size_t len = 0;

    CT_ASSERT_EQ_INT(pair_setup(&p), 0);

    CT_ASSERT_EQ_INT(cairn_node_beacon(&p.a, buf, sizeof buf, &len), CAIRN_OK);
    CT_ASSERT_EQ_INT(cairn_node_on_beacon(&p.b, buf, len, 1000), CAIRN_OK);
    CT_ASSERT_EQ_INT(cairn_node_neighbour_count(&p.b), 1);

    /* A node must not learn itself from its own beacon coming back. */
    CT_ASSERT_EQ_INT(cairn_node_on_beacon(&p.a, buf, len, 1000), CAIRN_OK);
    CT_ASSERT_EQ_INT(cairn_node_neighbour_count(&p.a), 0);

    CT_ASSERT_EQ_INT(cairn_node_beacon(&p.b, buf, sizeof buf, &len), CAIRN_OK);
    CT_ASSERT_EQ_INT(cairn_node_on_beacon(&p.a, buf, len, 1000), CAIRN_OK);
    CT_ASSERT_EQ_INT(cairn_node_neighbour_count(&p.a), 1);

    CT_ASSERT_MEM_EQ(p.a.neighbours.entries[0].id, p.idb.id, CAIRN_ID_BYTES);
    CT_ASSERT_MEM_EQ(p.a.neighbours.entries[0].name, "bob", 3);

    pair_teardown(&p);
}

/* The full handshake over frames, ending with both sides ready. */
CT_TEST(node_handshake_over_frames)
{
    pair p;
    cairn_outbox out, reply;

    CT_ASSERT_EQ_INT(pair_setup(&p), 0);
    CT_ASSERT_EQ_INT(cairn_node_peer_state(&p.a, p.idb.id), CAIRN_PEER_KNOWN);

    memset(&out, 0, sizeof out);
    CT_ASSERT_EQ_INT(cairn_node_connect(&p.a, p.idb.id, 1000, &out), CAIRN_OK);
    CT_ASSERT(out.len > 0);
    CT_ASSERT_EQ_INT(out.type, CAIRN_FRAME_HELLO);
    CT_ASSERT_EQ_INT(cairn_node_peer_state(&p.a, p.idb.id), CAIRN_PEER_HANDSHAKING);

    memset(&reply, 0, sizeof reply);
    CT_ASSERT_EQ_INT(deliver(&p.b, &out, 1000, &reply), CAIRN_OK);
    CT_ASSERT(reply.len > 0);
    CT_ASSERT_EQ_INT(reply.type, CAIRN_FRAME_ACCEPT);
    /* Answering is possible, but the channel is not usable until confirmed. */
    CT_ASSERT_EQ_INT(cairn_node_peer_state(&p.b, p.ida.id), CAIRN_PEER_HANDSHAKING);

    memset(&out, 0, sizeof out);
    CT_ASSERT_EQ_INT(deliver(&p.a, &reply, 1001, &out), CAIRN_OK);
    CT_ASSERT_EQ_INT(cairn_node_peer_state(&p.a, p.idb.id), CAIRN_PEER_READY);

    /* The initiator's confirmation travels back to the responder. */
    CT_ASSERT(out.len > 0);
    CT_ASSERT_EQ_INT(out.type, CAIRN_FRAME_ACK);
    memset(&reply, 0, sizeof reply);
    CT_ASSERT_EQ_INT(deliver(&p.b, &out, 1002, &reply), CAIRN_OK);
    CT_ASSERT_EQ_INT(cairn_node_peer_state(&p.b, p.ida.id), CAIRN_PEER_READY);

    pair_teardown(&p);
}

/* A passive node must be able to answer a HELLO it never asked for. */
CT_TEST(node_accept_after_hello)
{
    pair p;
    cairn_outbox out, reply, again;
    cairn_node passive;

    CT_ASSERT_EQ_INT(pair_setup(&p), 0);
    /* A fresh node with no prior knowledge of the peer at all. */
    CT_ASSERT_EQ_INT(cairn_node_init(&passive, &p.idb, "bob", 9102), CAIRN_OK);

    memset(&out, 0, sizeof out);
    CT_ASSERT_EQ_INT(cairn_node_connect(&p.a, p.idb.id, 1000, &out), CAIRN_OK);

    memset(&reply, 0, sizeof reply);
    CT_ASSERT_EQ_INT(deliver(&passive, &out, 1000, &reply), CAIRN_OK);
    CT_ASSERT(reply.len > 0);
    CT_ASSERT_EQ_INT(reply.type, CAIRN_FRAME_ACCEPT);
    CT_ASSERT_EQ_INT(cairn_node_peer_state(&passive, p.ida.id), CAIRN_PEER_HANDSHAKING);

    /* Accepting explicitly must rebuild the same reply from the live session. */
    memset(&again, 0, sizeof again);
    CT_ASSERT_EQ_INT(cairn_node_accept(&passive, p.ida.id, 1001, &again), CAIRN_OK);
    CT_ASSERT_EQ_INT(again.type, CAIRN_FRAME_ACCEPT);
    CT_ASSERT_EQ_INT(again.len, reply.len);
    CT_ASSERT_MEM_EQ(again.buf, reply.buf, reply.len);

    cairn_node_clear(&passive);
    pair_teardown(&p);
}

/* End to end: a message crosses a ready channel and arrives byte identical. */
CT_TEST(node_message_end_to_end)
{
    pair p;
    cairn_outbox out, reply;

    CT_ASSERT_EQ_INT(pair_setup(&p), 0);
    CT_ASSERT_EQ_INT(complete_handshake(&p), 0);

    memset(&out, 0, sizeof out);
    CT_ASSERT_EQ_INT(cairn_node_send(&p.a, p.idb.id, "hello over bluetooth", 20,
                                     &out), CAIRN_OK);
    CT_ASSERT_EQ_INT(out.type, CAIRN_FRAME_DATA);

    /* The frame carries ciphertext; the receiver exposes the plaintext. */
    memset(&reply, 0, sizeof reply);
    CT_ASSERT_EQ_INT(deliver(&p.b, &out, 1100, &reply), CAIRN_OK);
    CT_ASSERT_EQ_INT(p.b.peers[0].last_plain_len, 20);
    CT_ASSERT_MEM_EQ(p.b.peers[0].last_plain, "hello over bluetooth", 20);

    pair_teardown(&p);
}

/* Sending before the channel is proven must be refused. */
CT_TEST(node_send_requires_ready)
{
    pair p;
    cairn_outbox out;

    CT_ASSERT_EQ_INT(pair_setup(&p), 0);
    memset(&out, 0, sizeof out);
    CT_ASSERT_EQ_INT(cairn_node_send(&p.a, p.idb.id, "x", 1, &out), CAIRN_ERR_STATE);
    CT_ASSERT_EQ_INT(out.len, 0);

    pair_teardown(&p);
}

/* A tampered data frame must fail, and no plaintext may be delivered. */
CT_TEST(node_tampered_frame_rejected)
{
    pair p;
    cairn_outbox out, reply;

    CT_ASSERT_EQ_INT(pair_setup(&p), 0);
    CT_ASSERT_EQ_INT(complete_handshake(&p), 0);

    memset(&out, 0, sizeof out);
    CT_ASSERT_EQ_INT(cairn_node_send(&p.a, p.idb.id, "secret", 6, &out), CAIRN_OK);
    /* Flip a byte inside the payload region of the encoded frame. */
    out.buf[CAIRN_FRAME_OVERHEAD] ^= 0x01;

    memset(&reply, 0, sizeof reply);
    CT_ASSERT(deliver(&p.b, &out, 1100, &reply) != CAIRN_OK);
    CT_ASSERT_EQ_INT(p.b.peers[0].last_plain_len, 0);

    pair_teardown(&p);
}

/* A file transfer must stream chunks and finish only when all are confirmed. */
CT_TEST(node_transfer_streams_and_completes)
{
    pair p;
    cairn_outbox out, reply;
    uint8_t chunk[CAIRN_CHUNK_BYTES];
    uint64_t total = (uint64_t)CAIRN_CHUNK_BYTES * 3;
    int guard;

    CT_ASSERT_EQ_INT(pair_setup(&p), 0);
    CT_ASSERT_EQ_INT(complete_handshake(&p), 0);

    memset(&out, 0, sizeof out);
    CT_ASSERT_EQ_INT(cairn_node_offer_file(&p.a, p.idb.id, total, &out), CAIRN_OK);
    CT_ASSERT_EQ_INT(out.type, CAIRN_FRAME_XFER_META);

    memset(&reply, 0, sizeof reply);
    CT_ASSERT_EQ_INT(deliver(&p.b, &out, 1100, &reply), CAIRN_OK);
    CT_ASSERT(reply.len > 0);

    memset(chunk, 0x5a, sizeof chunk);
    for (guard = 0; guard < 16; guard++) {
        memset(&out, 0, sizeof out);
        if (cairn_node_pump_transfer(&p.a, p.idb.id, chunk, sizeof chunk, &out)
            != CAIRN_OK) break;
        if (out.len == 0) break;

        memset(&reply, 0, sizeof reply);
        CT_ASSERT_EQ_INT(deliver(&p.b, &out, 1200, &reply), CAIRN_OK);

        if (reply.len > 0) {
            cairn_outbox ack_reply;
            memset(&ack_reply, 0, sizeof ack_reply);
            CT_ASSERT_EQ_INT(deliver(&p.a, &reply, 1201, &ack_reply), CAIRN_OK);
        }
    }

    CT_ASSERT_EQ_INT(cairn_transfer_complete(&p.a.peers[0].transfer), 1);
    CT_ASSERT_EQ_INT(cairn_transfer_progress(&p.b.peers[0].transfer), total);

    pair_teardown(&p);
}

/* An interrupted transfer must resume from the first gap, not from zero. */
CT_TEST(node_transfer_resumes_after_drop)
{
    pair p;
    cairn_outbox out, reply;
    uint8_t chunk[CAIRN_CHUNK_BYTES];
    uint64_t total = (uint64_t)CAIRN_CHUNK_BYTES * 6;
    uint32_t index = 0;
    size_t len = 0;

    CT_ASSERT_EQ_INT(pair_setup(&p), 0);
    CT_ASSERT_EQ_INT(complete_handshake(&p), 0);

    memset(&out, 0, sizeof out);
    CT_ASSERT_EQ_INT(cairn_node_offer_file(&p.a, p.idb.id, total, &out), CAIRN_OK);
    memset(&reply, 0, sizeof reply);
    CT_ASSERT_EQ_INT(deliver(&p.b, &out, 1100, &reply), CAIRN_OK);

    /* Push two chunks through normally. */
    memset(chunk, 0x11, sizeof chunk);
    for (int i = 0; i < 2; i++) {
        memset(&out, 0, sizeof out);
        CT_ASSERT_EQ_INT(cairn_node_pump_transfer(&p.a, p.idb.id, chunk,
                                                  sizeof chunk, &out), CAIRN_OK);
        memset(&reply, 0, sizeof reply);
        CT_ASSERT_EQ_INT(deliver(&p.b, &out, 1200, &reply), CAIRN_OK);
        if (reply.len > 0) {
            cairn_outbox ack_reply;
            memset(&ack_reply, 0, sizeof ack_reply);
            CT_ASSERT_EQ_INT(deliver(&p.a, &reply, 1201, &ack_reply), CAIRN_OK);
        }
    }

    /* The link drops. */
    CT_ASSERT_EQ_INT(cairn_transfer_interrupt(&p.a.peers[0].transfer), CAIRN_OK);
    CT_ASSERT_EQ_INT(cairn_transfer_resume(&p.a.peers[0].transfer), CAIRN_OK);

    /* It must continue at chunk 2, with the same chunk length as before. */
    CT_ASSERT_EQ_INT(cairn_transfer_next_chunk(&p.a.peers[0].transfer, &index, &len),
                     CAIRN_OK);
    CT_ASSERT_EQ_INT(index, 2);
    CT_ASSERT_EQ_INT(len, CAIRN_CHUNK_BYTES);

    pair_teardown(&p);
}

CT_TEST(node_args_rejected)
{
    cairn_node n;
    cairn_outbox out;

    memset(&n, 0, sizeof n);
    CT_ASSERT_EQ_INT(cairn_node_connect(&n, NULL, 0, &out), CAIRN_ERR_ARG);
    CT_ASSERT_EQ_INT(cairn_node_on_frame(&n, NULL, 0, &out), CAIRN_ERR_ARG);
    CT_ASSERT_EQ_INT(cairn_node_init(NULL, NULL, NULL, 0), CAIRN_ERR_ARG);
    cairn_node_clear(NULL);
}

void ct_reg_node(void)
{
    CT_REG(node_beacons_cross_discover);
    CT_REG(node_handshake_over_frames);
    CT_REG(node_accept_after_hello);
    CT_REG(node_message_end_to_end);
    CT_REG(node_send_requires_ready);
    CT_REG(node_tampered_frame_rejected);
    CT_REG(node_transfer_streams_and_completes);
    CT_REG(node_transfer_resumes_after_drop);
    CT_REG(node_args_rejected);
}