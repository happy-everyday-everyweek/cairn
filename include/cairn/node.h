/* cairn: node orchestration.
 *
 * A node is the whole library assembled: an identity, a discovery beacon, a
 * neighbour table, a session per peer and a transfer per file. It is deliberately
 * not a framework. There is no event loop, no thread, no socket: the caller hands
 * the node bytes it received and asks for bytes to send. That keeps the library
 * usable from a CLI with one select loop, from an Android service with its own
 * callbacks, and from a test with two nodes talking in memory.
 *
 * A beacon carries only the peer id and a truncated fingerprint, which is enough
 * to recognise a device but not enough to run a handshake against. The full
 * public key arrives either by the caller registering it (a paired device from
 * storage) or inside the peer's HELLO frame. So the flow is:
 *
 *   cairn_node_init(&node, &identity, "name", port);
 *   cairn_node_beacon(&node, buf, &len);              publish this
 *   cairn_node_on_beacon(&node, buf, len, now);       learn peers
 *   cairn_node_add_peer(&node, &peer_key, "name");    register a paired peer
 *   cairn_node_connect(&node, peer_id, now, &out);    begin a handshake
 *   cairn_node_on_frame(&node, frame, now, &out);     feed every inbound frame
 *   cairn_node_send(&node, peer_id, data, len, &out); queue a message
 *
 * The node test runs exactly this sequence over an in-memory loopback, which is
 * the same code path a Bluetooth or Wi-Fi Direct link uses.
 */
#ifndef CAIRN_NODE_H
#define CAIRN_NODE_H

#include <stddef.h>
#include <stdint.h>

#include "cairn/cairn.h"
#include "cairn/crypto.h"
#include "cairn/discovery.h"
#include "cairn/identity.h"
#include "cairn/session.h"
#include "cairn/transfer.h"
#include "cairn/wire.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Simultaneous peers a node can track. One session each. */
#define CAIRN_NODE_MAX_SESSIONS 8

/* Largest payload a node will accept or queue for one message. */
#define CAIRN_NODE_MAX_PAYLOAD 60000

/* HELLO carries the sender's public key followed by the X3DH init blob, so the
 * responder can bind the static key and answer in one step. */
#define CAIRN_HELLO_BYTES (CAIRN_PUBKEY_BYTES + CAIRN_HANDSHAKE_INIT_BYTES)

/* ACCEPT carries the responder ephemeral plus its confirmation tag. */
#define CAIRN_ACCEPT_BYTES (CAIRN_HANDSHAKE_RESP_BYTES + CAIRN_TAG_BYTES)

typedef enum {
    CAIRN_PEER_EMPTY = 0,
    CAIRN_PEER_KNOWN = 1,       /* key learned, no handshake yet */
    CAIRN_PEER_HANDSHAKING = 2,
    CAIRN_PEER_READY = 3,
    CAIRN_PEER_FAILED = 4
} cairn_peer_state;

typedef struct {
    cairn_peer_state state;
    uint8_t id[CAIRN_ID_BYTES];
    cairn_pubkey key;
    char name[CAIRN_NAME_MAX + 1];
    cairn_session session;
    cairn_transfer transfer;
    /* Set once the peer proved it derived the same keys. Data never goes out
     * before this is true. */
    int confirmed;
    int initiated;
    /* Plaintext of the most recent inbound message. The node cannot call back
     * into the application, so it exposes the last delivered message instead. */
    uint8_t last_plain[CAIRN_NODE_MAX_PAYLOAD];
    size_t last_plain_len;
} cairn_peer;

typedef struct {
    cairn_identity identity;
    cairn_beacon beacon;
    cairn_neighbours neighbours;
    cairn_peer peers[CAIRN_NODE_MAX_SESSIONS];
    uint16_t port;
    int started;
} cairn_node;

/* One outbound frame. The caller drains this and writes the bytes wherever the
 * transport wants them. */
typedef struct {
    uint8_t type;
    size_t len;
    uint8_t buf[CAIRN_FRAME_MAX + CAIRN_FRAME_OVERHEAD];
} cairn_outbox;

int cairn_node_init(cairn_node *n, const cairn_identity *id, const char *name,
                    uint16_t port);

/* Produces this node's beacon. */
int cairn_node_beacon(const cairn_node *n, uint8_t *out, size_t outcap, size_t *outlen);

/* Records a beacon heard from the network. */
int cairn_node_on_beacon(cairn_node *n, const void *buf, size_t len, uint32_t now_ms);

/* Registers a peer's full public key, for a device already paired or reached out
 * of band. Without this, the handshake only starts once the peer says HELLO. */
int cairn_node_add_peer(cairn_node *n, const cairn_pubkey *key, const char *name);

/* Answers a beacon with this node's full public key, so a peer that has only
 * heard our beacon can start a handshake with us. */
int cairn_node_announce_key(cairn_node *n, const uint8_t peer_id[CAIRN_ID_BYTES],
                            cairn_outbox *out);

/* Announces this node to a peer, so that peer can run the handshake. Produces a
 * HELLO frame carrying our public key and an init blob. The peer's key must be
 * known. */
int cairn_node_connect(cairn_node *n, const uint8_t peer_id[CAIRN_ID_BYTES],
                       uint32_t now_ms, cairn_outbox *out);

/* Accepts a HELLO and produces the ACCEPT reply. */
int cairn_node_accept(cairn_node *n, const uint8_t peer_id[CAIRN_ID_BYTES],
                      uint32_t now_ms, cairn_outbox *out);

/* Feeds one inbound frame. Any reply is placed in out, whose len is 0 when no
 * reply is due. Passing NULL for out is allowed when the reply is not needed. */
int cairn_node_on_frame(cairn_node *n, const cairn_frame *f, uint32_t now_ms,
                        cairn_outbox *out);

/* Sends a message to a ready peer. A peer that has not confirmed the session is
 * refused, so plaintext never goes out on an unproven channel. */
int cairn_node_send(cairn_node *n, const uint8_t peer_id[CAIRN_ID_BYTES],
                    const void *data, size_t len, cairn_outbox *out);

/* Offers a file to a ready peer, then streams it one chunk per call. */
int cairn_node_offer_file(cairn_node *n, const uint8_t peer_id[CAIRN_ID_BYTES],
                          uint64_t total_bytes, cairn_outbox *out);
int cairn_node_pump_transfer(cairn_node *n, const uint8_t peer_id[CAIRN_ID_BYTES],
                             const void *chunk, size_t len, cairn_outbox *out);

int cairn_node_peer_state(const cairn_node *n, const uint8_t peer_id[CAIRN_ID_BYTES]);
int cairn_node_peer_count(const cairn_node *n);
int cairn_node_neighbour_count(const cairn_node *n);

void cairn_node_clear(cairn_node *n);

#ifdef __cplusplus
}
#endif

#endif /* CAIRN_NODE_H */