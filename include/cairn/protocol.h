/* cairn: node orchestration (lower layer).
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
 *   cairn_engine_init(&node, &identity, "name", port);
 *   cairn_engine_beacon(&node, buf, &len);              publish this
 *   cairn_engine_on_beacon(&node, buf, len, now);       learn peers
 *   cairn_engine_add_peer(&node, &peer_key, "name");    register a paired peer
 *   cairn_engine_connect(&node, peer_id, now, &out);    begin a handshake
 *   cairn_engine_on_frame(&node, frame, now, &out);     feed every inbound frame
 *   cairn_engine_send(&node, peer_id, data, len, &out); queue a message
 *
 * The node test runs exactly this sequence over an in-memory loopback, which is
 * the same code path a Bluetooth or Wi-Fi Direct link uses.
 */
#ifndef CAIRN_PROTOCOL_H
#define CAIRN_PROTOCOL_H

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
    CAIRN_ENGINE_EMPTY = 0,
    CAIRN_ENGINE_KNOWN = 1,       /* key learned, no handshake yet */
    CAIRN_ENGINE_HANDSHAKING = 2,
    CAIRN_ENGINE_READY = 3,
    CAIRN_ENGINE_FAILED = 4
} cairn_engine_peer_state_t;

typedef struct {
    cairn_engine_peer_state_t state;
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
    /* Decrypted bytes of the most recent inbound chunk. */
    uint8_t chunk_plain[CAIRN_CHUNK_BYTES];
    size_t chunk_plain_len;
    uint32_t chunk_index;
    /* Set once a KEY frame has filled in the peer's full public key. A slot created
     * from a beacon alone has no key and cannot be handshaked against. */
    int has_key;
    /* The pairing code bound into the handshake, as digits. Zero means none, in
     * which case the labels fall back to their bare form. */
    char code[13];
    int notified;
} cairn_engine_peer;

typedef struct {
    cairn_identity identity;
    cairn_beacon beacon;
    cairn_neighbours neighbours;
    cairn_engine_peer peers[CAIRN_NODE_MAX_SESSIONS];
    uint16_t port;
    int started;
    /* Optional callback for inbound chunks. Without it the bytes stay in the
     * peer's chunk_plain buffer for the caller to poll. */
    cairn_chunk_cb sink;
    void *sink_user;
    /* Pairing code applied to peers created after this call, empty when none. */
    char code[13];
} cairn_engine;

/* One outbound frame. The caller drains this and writes the bytes wherever the
 * transport wants them. */
typedef struct {
    uint8_t type;
    size_t len;
    uint8_t buf[CAIRN_FRAME_MAX + CAIRN_FRAME_OVERHEAD];
} cairn_engine_outbox;

int cairn_engine_init(cairn_engine *n, const cairn_identity *id, const char *name,
                    uint16_t port);

/* Produces this node's beacon. */
int cairn_engine_beacon(const cairn_engine *n, uint8_t *out, size_t outcap, size_t *outlen);

/* Records a beacon heard from the network. */
int cairn_engine_on_beacon(cairn_engine *n, const void *buf, size_t len, uint32_t now_ms);

/* Registers a peer's full public key, for a device already paired or reached out
 * of band. Without this, the handshake only starts once the peer says HELLO. */
int cairn_engine_add_peer(cairn_engine *n, const cairn_pubkey *key, const char *name);

/* Answers a beacon with this node's full public key, so a peer that has only
 * heard our beacon can start a handshake with us. */
int cairn_engine_announce_key(cairn_engine *n, const uint8_t peer_id[CAIRN_ID_BYTES],
                            cairn_engine_outbox *out);

/* Announces this node to a peer, so that peer can run the handshake. Produces a
 * HELLO frame carrying our public key and an init blob. The peer's key must be
 * known. */
int cairn_engine_connect(cairn_engine *n, const uint8_t peer_id[CAIRN_ID_BYTES],
                       uint32_t now_ms, cairn_engine_outbox *out);

/* Accepts a HELLO and produces the ACCEPT reply. */
int cairn_engine_accept(cairn_engine *n, const uint8_t peer_id[CAIRN_ID_BYTES],
                      uint32_t now_ms, cairn_engine_outbox *out);

/* Feeds one inbound frame. Any reply is placed in out, whose len is 0 when no
 * reply is due. Passing NULL for out is allowed when the reply is not needed. */
int cairn_engine_on_frame(cairn_engine *n, const cairn_frame *f, uint32_t now_ms,
                        cairn_engine_outbox *out);

/* Sends a message to a ready peer. A peer that has not confirmed the session is
 * refused, so plaintext never goes out on an unproven channel. */
int cairn_engine_send(cairn_engine *n, const uint8_t peer_id[CAIRN_ID_BYTES],
                    const void *data, size_t len, cairn_engine_outbox *out);

/* Offers a file to a ready peer, then streams it one chunk per call. */
int cairn_engine_offer_file(cairn_engine *n, const uint8_t peer_id[CAIRN_ID_BYTES],
                          uint64_t total_bytes, cairn_engine_outbox *out);
int cairn_engine_pump_transfer(cairn_engine *n, const uint8_t peer_id[CAIRN_ID_BYTES],
                             const void *chunk, size_t len, cairn_engine_outbox *out);

int cairn_engine_peer_status(const cairn_engine *n, const uint8_t peer_id[CAIRN_ID_BYTES]);

/* ---------------------------------------------------------- pairing decisions
 *
 * What the facade should do for one peer, decided purely from facts so it can be
 * checked exhaustively without a socket or a clock.
 *
 * The logic that used to sit inside cairn_pair_wait was tangled with timers and
 * file descriptors, and every bug in it lived in the branching rather than in the
 * I/O: a flag carried across passes made a lost datagram unrecoverable, and a
 * missing "do we hold their key" check deadlocked both sides. Pulling the decision
 * out makes those cases a table.
 */
typedef enum {
    CAIRN_PAIR_IDLE = 0,     /* nothing to do this pass */
    CAIRN_PAIR_SEND_KEY,     /* we still lack their key, so send ours */
    CAIRN_PAIR_SEND_HELLO    /* both keys held, and we are the initiator */
} cairn_pair_action;

typedef struct {
    int peer_state;   /* a cairn_engine_peer_state_t value */
    int has_key;      /* we hold the peer's full public key */
    int we_initiate;  /* our device id sorts lower, so HELLO is ours to send */
    int key_due;      /* the key retransmit timer has elapsed */
    int hello_due;    /* the HELLO retransmit timer has elapsed */
} cairn_pair_view;

/* Returns what to send for this peer, or IDLE. */
cairn_pair_action cairn_pair_next(const cairn_pair_view *v);
/* Binds a pairing code to every current and future peer, so two devices only
 * complete a handshake when they used the same digits. NULL clears it. */
int cairn_engine_set_code(cairn_engine *n, const char *code);
int cairn_engine_peer_count(const cairn_engine *n);
int cairn_engine_neighbour_count(const cairn_engine *n);

void cairn_engine_clear(cairn_engine *n);

#ifdef __cplusplus
}
#endif

#endif /* CAIRN_PROTOCOL_H */