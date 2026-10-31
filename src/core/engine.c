/* cairn: node assembly.
 *
 * The node owns no I/O. It takes frames in, produces frames out, and every piece
 * of state it keeps belongs to a module underneath: identity, discovery, session,
 * transfer. That is why the end to end test can run two nodes through a hand
 * written loopback and cover the same code a radio would drive.
 *
 * Handshake over frames:
 *
 *   HELLO  our public key || session init blob
 *   ACCEPT responder ephemeral || responder confirmation tag
 *   ACK    initiator confirmation tag
 *
 * The HELLO carries the sender's full public key because a beacon only has room
 * for the id and a fingerprint prefix. The two tags are what make the channel
 * trustworthy: the responder proves it derived the same root before the initiator
 * marks the channel ready, and the initiator proves the same before the responder
 * does.
 */
#include "cairn/protocol.h"

#include <stdio.h>
#include <string.h>

static void put_u32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

static uint32_t get_u32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static void put_u64(uint8_t *p, uint64_t v)
{
    put_u32(p, (uint32_t)v);
    put_u32(p + 4, (uint32_t)(v >> 32));
}

static uint64_t get_u64(const uint8_t *p)
{
    return (uint64_t)get_u32(p) | ((uint64_t)get_u32(p + 4) << 32);
}

/* Writes one frame into the outbox. A NULL outbox means the caller does not want
 * the reply, which is allowed everywhere. */
static int emit(cairn_engine_outbox *out, uint8_t type, const void *payload, size_t len)
{
    size_t used = 0;
    int rc;

    if (out == NULL) return CAIRN_OK;
    out->len = 0;
    rc = cairn_frame_encode(out->buf, sizeof out->buf, &used, type, payload, len);
    if (rc != CAIRN_OK) return rc;
    out->type = type;
    out->len = used;
    return CAIRN_OK;
}

static int peer_index(const cairn_engine *n, const uint8_t id[CAIRN_ID_BYTES])
{
    int i;

    for (i = 0; i < CAIRN_NODE_MAX_SESSIONS; i++)
        if (n->peers[i].state != CAIRN_ENGINE_EMPTY &&
            memcmp(n->peers[i].id, id, CAIRN_ID_BYTES) == 0)
            return i;
    return -1;
}

static int peer_alloc(cairn_engine *n, const uint8_t id[CAIRN_ID_BYTES])
{
    int i;

    for (i = 0; i < CAIRN_NODE_MAX_SESSIONS; i++) {
        if (n->peers[i].state == CAIRN_ENGINE_EMPTY) {
            memset(&n->peers[i], 0, sizeof n->peers[i]);
            memcpy(n->peers[i].id, id, CAIRN_ID_BYTES);
            if (n->code[0] != '\0')
                strncpy(n->peers[i].code, n->code, sizeof n->peers[i].code - 1);
            n->peers[i].state = CAIRN_ENGINE_KNOWN;
            return i;
        }
    }
    return CAIRN_ERR_MEMORY;
}

/* Returns the slot for a known peer, creating a bare one when the caller is
 * registering a key it just learned. */
static int peer_slot(cairn_engine *n, const uint8_t id[CAIRN_ID_BYTES])
{
    int idx = peer_index(n, id);
    if (idx >= 0) return idx;
    return peer_alloc(n, id);
}

int cairn_engine_init(cairn_engine *n, const cairn_identity *id, const char *name,
                    uint16_t port)
{
    cairn_pubkey self;

    if (n == NULL || id == NULL) return CAIRN_ERR_ARG;

    memset(n, 0, sizeof *n);
    n->identity = *id;
    n->port = port;
    cairn_neighbours_clear(&n->neighbours);

    if (cairn_beacon_from_identity(&n->beacon, id, name != NULL ? name : "cairn",
                                   port, CAIRN_CAP_TRANSFER | CAIRN_CAP_CHAT)
        != CAIRN_OK)
        return CAIRN_ERR_CRYPTO;

    /* The identity blob is needed by every handshake, so materialise it once. */
    cairn_identity_pubkey(id, &self);
    n->started = 1;
    return CAIRN_OK;
}

int cairn_engine_beacon(const cairn_engine *n, uint8_t *out, size_t outcap, size_t *outlen)
{
    if (n == NULL || !n->started) return CAIRN_ERR_STATE;
    return cairn_beacon_encode(out, outcap, outlen, &n->beacon);
}

int cairn_engine_on_beacon(cairn_engine *n, const void *buf, size_t len, uint32_t now_ms)
{
    cairn_beacon b;
    int rc, idx;

    if (n == NULL || !n->started) return CAIRN_ERR_STATE;

    rc = cairn_beacon_decode(&b, buf, len);
    if (rc != CAIRN_OK) return rc;

    /* Our own beacon can come back through a multicast loop; ignore it. */
    if (memcmp(b.id, n->beacon.id, CAIRN_ID_BYTES) == 0) return CAIRN_OK;

    /* Recording the neighbour is what makes a device discoverable, but a neighbour is not
     * yet a peer: the beacon carries only an id and a fingerprint prefix, not the public
     * key a handshake needs. A slot is created in KNOWN so the caller can see that
     * someone is out there and answer with its key. The slot gains a usable key only
     * when a KEY frame arrives, and cairn_engine_connect refuses until then, which is
     * what stops a handshake being attempted against a zero key.
     */
    idx = peer_slot(n, b.id);
    if (idx >= 0 && n->peers[idx].state == CAIRN_ENGINE_EMPTY) {
        n->peers[idx].state = CAIRN_ENGINE_KNOWN;
        if (n->code[0] != '\0')
            strncpy(n->peers[idx].code, n->code, sizeof n->peers[idx].code - 1);
    }

    return cairn_neighbours_add(&n->neighbours, &b, now_ms);
}

int cairn_engine_add_peer(cairn_engine *n, const cairn_pubkey *key, const char *name)
{
    int idx;

    if (n == NULL || key == NULL || !n->started) return CAIRN_ERR_ARG;

    idx = peer_slot(n, key->id);
    if (idx < 0) return idx;

    /* Re-registering a key for a live session would silently change the peer's
     * identity, so refuse once the channel is up. */
    if (n->peers[idx].state == CAIRN_ENGINE_READY ||
        n->peers[idx].state == CAIRN_ENGINE_HANDSHAKING)
        return CAIRN_ERR_STATE;

    n->peers[idx].key = *key;
    n->peers[idx].has_key = 1;
    n->peers[idx].state = CAIRN_ENGINE_KNOWN;
    n->peers[idx].confirmed = 0;
    n->peers[idx].initiated = 0;
    n->peers[idx].last_plain_len = 0;
    if (name != NULL) {
        size_t k = strlen(name);
        if (k > CAIRN_NAME_MAX) k = CAIRN_NAME_MAX;
        memcpy(n->peers[idx].name, name, k);
        n->peers[idx].name[k] = '\0';
    }
    return CAIRN_OK;
}

int cairn_engine_connect(cairn_engine *n, const uint8_t peer_id[CAIRN_ID_BYTES],
                       uint32_t now_ms, cairn_engine_outbox *out)
{
    uint8_t hello[CAIRN_HELLO_BYTES];
    cairn_pubkey self;
    cairn_engine_peer *p;
    int idx, rc;

    (void)now_ms;
    if (n == NULL || peer_id == NULL || !n->started) return CAIRN_ERR_ARG;

    idx = peer_index(n, peer_id);
    if (idx < 0) return CAIRN_ERR_STATE;
    p = &n->peers[idx];

    /* A handshake we already started is retransmitted, not restarted. The stored
     * bytes matter: cairn_session_init would derive a fresh init secret, and the
     * responder's ACCEPT is only valid for the blob it actually answered. */
    if (p->state == CAIRN_ENGINE_HANDSHAKING && p->initiated &&
        p->hello_len == sizeof hello)
        return emit(out, CAIRN_FRAME_HELLO, p->hello, p->hello_len);

    if (p->state != CAIRN_ENGINE_KNOWN) return CAIRN_ERR_STATE;
    /* A slot seen only in a beacon has no public key; a handshake against zeroes would
     * fail deep inside X25519 instead of here. */
    if (!p->has_key) return CAIRN_ERR_STATE;

    rc = cairn_session_init(&p->session, &n->identity, &p->key,
                            hello + CAIRN_PUBKEY_BYTES);
    if (rc != CAIRN_OK) {
        p->state = CAIRN_ENGINE_FAILED;
        return rc;
    }

    cairn_identity_pubkey(&n->identity, &self);
    cairn_pubkey_encode(hello, &self);

    memcpy(p->hello, hello, sizeof hello);
    p->hello_len = sizeof hello;
    p->state = CAIRN_ENGINE_HANDSHAKING;
    p->initiated = 1;
    return emit(out, CAIRN_FRAME_HELLO, hello, sizeof hello);
}

int cairn_engine_announce_key(cairn_engine *n, const uint8_t peer_id[CAIRN_ID_BYTES],
                              cairn_engine_outbox *out)
{
    cairn_pubkey self;
    uint8_t wire[CAIRN_PUBKEY_BYTES];

    if (n == NULL || !n->started) return CAIRN_ERR_ARG;
    /* peer_id is only a hint about who is listening; the frame itself is our own
     * key, so it is safe to send even to a peer we barely know. */
    (void)peer_id;

    cairn_identity_pubkey(&n->identity, &self);
    cairn_pubkey_encode(wire, &self);
    return emit(out, CAIRN_FRAME_KEY, wire, sizeof wire);
}

int cairn_engine_set_code(cairn_engine *n, const char *code)
{
    int i;

    if (n == NULL) return CAIRN_ERR_ARG;
    if (code != NULL && strlen(code) > 12) return CAIRN_ERR_ARG;

    /* The code applies to every slot, including one created later, so it is
     * stamped on the engine and copied into a peer when that peer appears. */
    memset(n->code, 0, sizeof n->code);
    if (code != NULL) strncpy(n->code, code, sizeof n->code - 1);

    for (i = 0; i < CAIRN_NODE_MAX_SESSIONS; i++) {
        memset(n->peers[i].code, 0, sizeof n->peers[i].code);
        if (code != NULL) strncpy(n->peers[i].code, code, sizeof n->peers[i].code - 1);
    }
    return CAIRN_OK;
}

/* ---------------------------------------------------------- pairing decisions */

/* The whole pairing decision, in one place and with no side effects.
 *
 * Three rules, in order:
 *
 *   without the peer's key there is only one useful thing to send: ours. This must
 *   come first, because requiring their key before sending ours deadlocks two
 *   devices that each wait for the other.
 *   with both keys held, only one side should send HELLO, and we_initiate says
 *   which. Both sides compute it from the same two device ids, so they never both
 *   send one.
 *   a peer already handshaking or finished is left alone; retransmission of those
 *   phases is the caller's business, not this function's.
 */
cairn_pair_action cairn_pair_next(const cairn_pair_view *v)
{
    if (v == NULL) return CAIRN_PAIR_IDLE;

    if (v->peer_state == CAIRN_ENGINE_EMPTY || v->peer_state == CAIRN_ENGINE_READY)
        return CAIRN_PAIR_IDLE;

    if (!v->has_key) return v->key_due ? CAIRN_PAIR_SEND_KEY : CAIRN_PAIR_IDLE;

    if (v->peer_state == CAIRN_ENGINE_KNOWN) {
        if (v->we_initiate && v->hello_due) return CAIRN_PAIR_SEND_HELLO;
        return CAIRN_PAIR_IDLE;
    }

    /* A handshake in flight is retransmitted, not restarted. Without this a single
     * lost HELLO or ACCEPT left both sides waiting until the timeout expired, which
     * is what made pairing succeed on one run and fail on the next. Both
     * retransmissions are idempotent: the HELLO is resent byte for byte, and the
     * ACCEPT is rebuilt from the session the responder already holds. */
    if (v->peer_state == CAIRN_ENGINE_HANDSHAKING) {
        if (v->we_initiate) return v->hello_due ? CAIRN_PAIR_SEND_HELLO : CAIRN_PAIR_IDLE;
        return v->accept_due ? CAIRN_PAIR_SEND_ACCEPT : CAIRN_PAIR_IDLE;
    }

    return CAIRN_PAIR_IDLE;
}

/* Builds the label a confirmation tag is keyed with.
 *
 * The pairing code goes in here, and that is the whole point: the tag is derived
 * from the root key and this label, so two devices that used different codes
 * compute different tags and the handshake fails with CAIRN_ERR_AUTH. Nobody who
 * only observes the traffic can produce a matching tag either, because producing
 * it needs the root key.
 *
 * Without a code the label is the bare phase name, which keeps the engine usable
 * on its own for a caller that has already authenticated the peer by other means.
 */
static void phase_label(char out[32], const cairn_engine_peer *p, const char *phase)
{
    if (p->code[0] == '\0') {
        snprintf(out, 32, "%s", phase);
        return;
    }
    /* A separator keeps "1" + "23" from colliding with "12" + "3". */
    snprintf(out, 32, "%s|%s", phase, p->code);
}

/* Rebuilds the ACCEPT reply from the session the responder already holds. Used both
 * for the first answer and for every retransmission, so a lost ACCEPT can never
 * leave the initiator waiting for a reply that will not come again. */
static int emit_accept(const cairn_engine_peer *p, cairn_engine_outbox *out)
{
    uint8_t accept[CAIRN_ACCEPT_BYTES];
    char label[32];
    int rc;

    memcpy(accept, p->session.send_dh_pub, CAIRN_HANDSHAKE_RESP_BYTES);
    phase_label(label, p, "accept");
    rc = cairn_session_confirm_tag(accept + CAIRN_HANDSHAKE_RESP_BYTES, &p->session, label);
    if (rc != CAIRN_OK) return rc;
    return emit(out, CAIRN_FRAME_ACCEPT, accept, sizeof accept);
}

/* Applies a HELLO: binds the sender's key and parks the responder side of the
 * handshake. Shared by cairn_engine_on_frame and cairn_engine_accept.
 *
 * A repeated HELLO is answered from the session already bound, not by running the
 * responder again. Re-running it would mint a new ephemeral and a new root, while the
 * initiator is still holding the keys derived from its original blob; the two sides
 * would then disagree forever. */
static int handle_hello(cairn_engine *n, const uint8_t *payload, size_t len,
                        cairn_engine_outbox *out)
{
    cairn_pubkey peer_pk;
    cairn_engine_peer *p;
    uint8_t ephemeral[CAIRN_HANDSHAKE_RESP_BYTES];
    int idx, rc;

    if (payload == NULL || len != CAIRN_HELLO_BYTES) return CAIRN_ERR_FORMAT;

    rc = cairn_pubkey_decode(&peer_pk, payload);
    if (rc != CAIRN_OK) return rc;

    idx = peer_index(n, peer_pk.id);
    if (idx >= 0) {
        p = &n->peers[idx];
        /* Already established: a late duplicate is harmless and must not disturb it. */
        if (p->state == CAIRN_ENGINE_READY) return CAIRN_OK;
        if (p->state == CAIRN_ENGINE_HANDSHAKING && !p->initiated &&
            p->session.established)
            return emit_accept(p, out);
    } else {
        idx = peer_slot(n, peer_pk.id);
        if (idx < 0) return idx;
    }
    p = &n->peers[idx];

    /* Trust on first use: the key in the HELLO replaces whatever we had, but only
     * while the channel is not established. */
    p->key = peer_pk;

    rc = cairn_session_respond(&p->session, &n->identity, ephemeral,
                               payload + CAIRN_PUBKEY_BYTES,
                               len - CAIRN_PUBKEY_BYTES);
    if (rc != CAIRN_OK) {
        p->state = CAIRN_ENGINE_FAILED;
        return rc;
    }

    p->state = CAIRN_ENGINE_HANDSHAKING;
    p->initiated = 0;
    return emit_accept(p, out);
}

int cairn_engine_accept(cairn_engine *n, const uint8_t peer_id[CAIRN_ID_BYTES],
                      uint32_t now_ms, cairn_engine_outbox *out)
{
    cairn_engine_peer *p;
    int idx;

    (void)now_ms;
    if (n == NULL || peer_id == NULL || !n->started) return CAIRN_ERR_ARG;

    idx = peer_index(n, peer_id);
    if (idx < 0) return CAIRN_ERR_STATE;
    p = &n->peers[idx];
    if (p->state != CAIRN_ENGINE_HANDSHAKING || p->initiated) return CAIRN_ERR_STATE;
    if (!p->session.established) return CAIRN_ERR_STATE;

    /* Rebuild the reply from the live session: the peer ephemeral already sits in
     * the session, so re-encoding it is enough. */
    return emit_accept(p, out);
}

/* Finds the single peer waiting on an ACCEPT, which is the one we initiated. */
static int find_initiating_peer(const cairn_engine *n)
{
    int i;

    for (i = 0; i < CAIRN_NODE_MAX_SESSIONS; i++)
        if (n->peers[i].state == CAIRN_ENGINE_HANDSHAKING && n->peers[i].initiated)
            return i;
    return -1;
}

static int find_responding_peer(const cairn_engine *n)
{
    int i;

    for (i = 0; i < CAIRN_NODE_MAX_SESSIONS; i++)
        if (n->peers[i].state == CAIRN_ENGINE_HANDSHAKING && !n->peers[i].initiated)
            return i;
    return -1;
}

static int handle_accept(cairn_engine *n, const uint8_t *payload, size_t len,
                         cairn_engine_outbox *out)
{
    uint8_t tag[CAIRN_TAG_BYTES];
    char label[32];
    int idx, rc, i;

    if (payload == NULL || len != CAIRN_ACCEPT_BYTES) return CAIRN_ERR_FORMAT;

    idx = find_initiating_peer(n);
    if (idx < 0) {
        /* No handshake of ours is in flight, so this is a repeated ACCEPT: the
         * responder is still waiting for our confirmation, which means the ACK we
         * sent was lost. Rebuild it from the session we already hold. */
        for (i = 0; i < CAIRN_NODE_MAX_SESSIONS; i++)
            if (n->peers[i].state == CAIRN_ENGINE_READY && n->peers[i].confirmed) break;
        if (i == CAIRN_NODE_MAX_SESSIONS) return CAIRN_ERR_STATE;

        phase_label(label, &n->peers[i], "confirm");
        rc = cairn_session_confirm_tag(tag, &n->peers[i].session, label);
        if (rc != CAIRN_OK) return rc;
        return emit(out, CAIRN_FRAME_ACK, tag, sizeof tag);
    }

    rc = cairn_session_finish(&n->peers[idx].session, payload,
                              CAIRN_HANDSHAKE_RESP_BYTES);
    if (rc != CAIRN_OK) {
        n->peers[idx].state = CAIRN_ENGINE_FAILED;
        return rc;
    }

    /* Only trust the channel once the responder has proved it holds our root AND
     * used our code. A different code makes this fail, which is the point. */
    phase_label(label, &n->peers[idx], "accept");
    if (cairn_session_check_tag(&n->peers[idx].session, label,
                               payload + CAIRN_HANDSHAKE_RESP_BYTES) != CAIRN_OK) {
        n->peers[idx].state = CAIRN_ENGINE_FAILED;
        return CAIRN_ERR_AUTH;
    }

    n->peers[idx].state = CAIRN_ENGINE_READY;
    n->peers[idx].confirmed = 1;

    phase_label(label, &n->peers[idx], "confirm");
    rc = cairn_session_confirm_tag(tag, &n->peers[idx].session, label);
    if (rc != CAIRN_OK) return rc;
    return emit(out, CAIRN_FRAME_ACK, tag, sizeof tag);
}

static int handle_confirm(cairn_engine *n, const uint8_t *payload, size_t len)
{
    char label[32];
    int idx;

    if (payload == NULL || len != CAIRN_TAG_BYTES) return CAIRN_ERR_FORMAT;

    idx = find_responding_peer(n);
    if (idx < 0) return CAIRN_ERR_STATE;

    phase_label(label, &n->peers[idx], "confirm");
    if (cairn_session_check_tag(&n->peers[idx].session, label, payload)
        != CAIRN_OK) {
        n->peers[idx].state = CAIRN_ENGINE_FAILED;
        return CAIRN_ERR_AUTH;
    }
    n->peers[idx].state = CAIRN_ENGINE_READY;
    n->peers[idx].confirmed = 1;
    return CAIRN_OK;
}

/* Data frames carry the ratchet header in the clear and the ciphertext after it.
 * Any ready peer is tried; the AEAD tag decides which one matches. */
static int handle_data(cairn_engine *n, const uint8_t *payload, size_t len)
{
    cairn_header hdr;
    int i;
    const size_t head = 8 + CAIRN_X25519_BYTES;

    if (payload == NULL) return CAIRN_ERR_ARG;
    if (len < head + CAIRN_TAG_BYTES) return CAIRN_ERR_FORMAT;

    hdr.epoch = get_u32(payload);
    hdr.index = get_u32(payload + 4);
    memcpy(hdr.dh_pub, payload + 8, CAIRN_X25519_BYTES);

    for (i = 0; i < CAIRN_NODE_MAX_SESSIONS; i++) {
        size_t ptlen = 0;
        int rc;

        if (n->peers[i].state != CAIRN_ENGINE_READY || !n->peers[i].confirmed)
            continue;

        rc = cairn_session_open(&n->peers[i].session, &hdr,
                                n->peers[i].last_plain,
                                sizeof n->peers[i].last_plain, &ptlen,
                                payload + head, len - head);
        if (rc == CAIRN_OK) {
            n->peers[i].last_plain_len = ptlen;
            return CAIRN_OK;
        }
        /* A tag failure just means this was not the peer's session. */
        if (rc != CAIRN_ERR_AUTH) return rc;
    }
    return CAIRN_ERR_AUTH;
}

/* Marks the first peer that arrived before the handshake and answers its HELLO
 * lazily, which is what cairn_engine_accept exists for. */
static int first_responding_peer(const cairn_engine *n)
{
    int i;

    for (i = 0; i < CAIRN_NODE_MAX_SESSIONS; i++)
        if (n->peers[i].state == CAIRN_ENGINE_HANDSHAKING && !n->peers[i].initiated)
            return i;
    return -1;
}

int cairn_engine_on_frame(cairn_engine *n, const cairn_frame *f, uint32_t now_ms,
                        cairn_engine_outbox *out)
{
    (void)now_ms;
    if (n == NULL || f == NULL || !n->started) return CAIRN_ERR_ARG;
    if (out != NULL) out->len = 0;

    switch (f->type) {
    case CAIRN_FRAME_HELLO:
        return handle_hello(n, f->payload, f->payloadlen, out);

    case CAIRN_FRAME_ACCEPT:
        return handle_accept(n, f->payload, f->payloadlen, out);

    case CAIRN_FRAME_ACK: {
        /* An ACK is either the handshake confirmation or a transfer
         * acknowledgement. The length disambiguates them. */
        if (f->payloadlen == CAIRN_TAG_BYTES) return handle_confirm(n, f->payload, f->payloadlen);

        if (f->payloadlen == 8) {
            int idx = first_responding_peer(n);
            uint32_t index = get_u32(f->payload);
            if (idx < 0) {
                /* No handshake pending: treat it as a transfer confirmation. */
                for (idx = 0; idx < CAIRN_NODE_MAX_SESSIONS; idx++)
                    if (n->peers[idx].state == CAIRN_ENGINE_READY) break;
                if (idx == CAIRN_NODE_MAX_SESSIONS) return CAIRN_ERR_STATE;
            }
            return cairn_transfer_ack(&n->peers[idx].transfer, index);
        }
        return CAIRN_ERR_FORMAT;
    }

    case CAIRN_FRAME_DATA:
        return handle_data(n, f->payload, f->payloadlen);

    case CAIRN_FRAME_XFER_META: {
        uint64_t total;
        int idx, rc;

        if (f->payloadlen != 8) return CAIRN_ERR_FORMAT;
        total = get_u64(f->payload);

        for (idx = 0; idx < CAIRN_NODE_MAX_SESSIONS; idx++)
            if (n->peers[idx].state == CAIRN_ENGINE_READY) break;
        if (idx == CAIRN_NODE_MAX_SESSIONS) return CAIRN_ERR_NOT_FOUND;

        rc = cairn_transfer_offer(&n->peers[idx].transfer, total);
        if (rc != CAIRN_OK) return rc;
        rc = cairn_transfer_accept(&n->peers[idx].transfer);
        if (rc != CAIRN_OK) return rc;

        /* Confirm the metadata so the sender may start streaming. */
        return emit(out, CAIRN_FRAME_ACK, f->payload, 8);
    }

    case CAIRN_FRAME_XFER_CHUNK: {
        cairn_header hdr;
        uint32_t index, chunk_len;
        size_t plain_len = 0;
        int idx, rc;

        /* epoch | index | length | ratchet key | ciphertext */
        if (f->payloadlen < 12 + CAIRN_X25519_BYTES + CAIRN_TAG_BYTES)
            return CAIRN_ERR_FORMAT;

        hdr.epoch = get_u32(f->payload);
        index = get_u32(f->payload + 4);
        chunk_len = get_u32(f->payload + 8);
        memcpy(hdr.dh_pub, f->payload + 12, CAIRN_X25519_BYTES);

        for (idx = 0; idx < CAIRN_NODE_MAX_SESSIONS; idx++)
            if (n->peers[idx].state == CAIRN_ENGINE_READY) break;
        if (idx == CAIRN_NODE_MAX_SESSIONS) return CAIRN_ERR_NOT_FOUND;

        if (chunk_len > CAIRN_CHUNK_BYTES) return CAIRN_ERR_FORMAT;

        rc = cairn_session_open(&n->peers[idx].session, &hdr,
                                n->peers[idx].chunk_plain, sizeof n->peers[idx].chunk_plain,
                                &plain_len,
                                f->payload + 12 + CAIRN_X25519_BYTES,
                                f->payloadlen - 12 - CAIRN_X25519_BYTES);
        if (rc != CAIRN_OK) return rc;
        if (plain_len != chunk_len) return CAIRN_ERR_FORMAT;

        rc = cairn_transfer_ack(&n->peers[idx].transfer, index);
        if (rc != CAIRN_OK)
            return CAIRN_ERR_FORMAT;

        /* Hand the bytes to the caller's sink, if it registered one. */
        if (n->sink != NULL)
            n->sink(n->sink_user, n->peers[idx].id, n->peers[idx].chunk_index,
                    n->peers[idx].chunk_plain, plain_len);
        n->peers[idx].chunk_index = index;
        n->peers[idx].chunk_plain_len = plain_len;

        {
            uint8_t ack[8];
            put_u32(ack, index);
            put_u32(ack + 4, chunk_len);
            return emit(out, CAIRN_FRAME_ACK, ack, sizeof ack);
        }
    }

    case CAIRN_FRAME_KEY: {
        cairn_pubkey pk;
        int rc;

        if (f->payloadlen != CAIRN_PUBKEY_BYTES) return CAIRN_ERR_FORMAT;
        rc = cairn_pubkey_decode(&pk, f->payload);
        if (rc != CAIRN_OK) return rc;
        /* An announced key is a bare credential, so it may only fill a slot that
         * has no live session yet. */
        return cairn_engine_add_peer(n, &pk, NULL);
    }

    case CAIRN_FRAME_PING:
        return emit(out, CAIRN_FRAME_PONG, NULL, 0);

    case CAIRN_FRAME_BYE:
    case CAIRN_FRAME_PONG:
    default:
        return CAIRN_OK;
    }
}

int cairn_engine_send(cairn_engine *n, const uint8_t peer_id[CAIRN_ID_BYTES],
                    const void *data, size_t len, cairn_engine_outbox *out)
{
    uint8_t payload[8 + CAIRN_X25519_BYTES + CAIRN_NODE_MAX_PAYLOAD];
    cairn_header hdr;
    size_t ctlen = 0;
    int idx, rc;

    if (n == NULL || peer_id == NULL || out == NULL) return CAIRN_ERR_ARG;
    if (data == NULL && len > 0) return CAIRN_ERR_ARG;
    if (len > CAIRN_NODE_MAX_PAYLOAD) return CAIRN_ERR_ARG;

    idx = peer_index(n, peer_id);
    if (idx < 0) return CAIRN_ERR_STATE;
    if (n->peers[idx].state != CAIRN_ENGINE_READY || !n->peers[idx].confirmed)
        return CAIRN_ERR_STATE;

    rc = cairn_session_seal(&n->peers[idx].session, &hdr,
                            payload + 8 + CAIRN_X25519_BYTES,
                            sizeof payload - 8 - CAIRN_X25519_BYTES, &ctlen,
                            data, len);
    if (rc != CAIRN_OK) return rc;

    put_u32(payload, hdr.epoch);
    put_u32(payload + 4, hdr.index);
    memcpy(payload + 8, hdr.dh_pub, CAIRN_X25519_BYTES);

    return emit(out, CAIRN_FRAME_DATA, payload, 8 + CAIRN_X25519_BYTES + ctlen);
}

int cairn_engine_offer_file(cairn_engine *n, const uint8_t peer_id[CAIRN_ID_BYTES],
                          uint64_t total_bytes, cairn_engine_outbox *out)
{
    uint8_t payload[8];
    int idx, rc;

    if (n == NULL || peer_id == NULL || out == NULL) return CAIRN_ERR_ARG;

    idx = peer_index(n, peer_id);
    if (idx < 0) return CAIRN_ERR_STATE;
    if (n->peers[idx].state != CAIRN_ENGINE_READY || !n->peers[idx].confirmed)
        return CAIRN_ERR_STATE;

    rc = cairn_transfer_offer(&n->peers[idx].transfer, total_bytes);
    if (rc != CAIRN_OK) return rc;
    rc = cairn_transfer_accept(&n->peers[idx].transfer);
    if (rc != CAIRN_OK) return rc;

    put_u64(payload, total_bytes);
    return emit(out, CAIRN_FRAME_XFER_META, payload, sizeof payload);
}

int cairn_engine_pump_transfer(cairn_engine *n, const uint8_t peer_id[CAIRN_ID_BYTES],
                             const void *chunk, size_t len, cairn_engine_outbox *out)
{
    uint8_t payload[12 + CAIRN_X25519_BYTES + CAIRN_CHUNK_BYTES + CAIRN_TAG_BYTES];
    uint32_t index = 0;
    size_t want = 0;
    cairn_header hdr;
    size_t ctlen = 0;
    int idx, rc;

    if (n == NULL || peer_id == NULL || chunk == NULL || out == NULL)
        return CAIRN_ERR_ARG;

    idx = peer_index(n, peer_id);
    if (idx < 0) return CAIRN_ERR_STATE;
    if (n->peers[idx].state != CAIRN_ENGINE_READY) return CAIRN_ERR_STATE;

    rc = cairn_transfer_next_chunk(&n->peers[idx].transfer, &index, &want);
    if (rc != CAIRN_OK) return rc;
    if (len < want) return CAIRN_ERR_ARG;

    /* The chunk is sealed exactly like a message, so the receiver needs the same
     * ratchet header to derive the key. Index and length travel alongside so the
     * receiver can acknowledge the right chunk. */
    rc = cairn_session_seal(&n->peers[idx].session, &hdr,
                            payload + 12 + CAIRN_X25519_BYTES,
                            sizeof payload - 12 - CAIRN_X25519_BYTES, &ctlen, chunk, want);
    if (rc != CAIRN_OK) return rc;

    put_u32(payload, hdr.epoch);
    put_u32(payload + 4, hdr.index);
    put_u32(payload + 8, (uint32_t)want);
    memcpy(payload + 12, hdr.dh_pub, CAIRN_X25519_BYTES);

    return emit(out, CAIRN_FRAME_XFER_CHUNK, payload,
                12 + CAIRN_X25519_BYTES + ctlen);
}

int cairn_engine_peer_status(const cairn_engine *n, const uint8_t peer_id[CAIRN_ID_BYTES])
{
    int idx;

    if (n == NULL || peer_id == NULL) return CAIRN_ERR_ARG;
    idx = peer_index(n, peer_id);
    if (idx < 0) return CAIRN_ENGINE_EMPTY;
    return n->peers[idx].state;
}

int cairn_engine_peer_count(const cairn_engine *n)
{
    int i, count = 0;

    if (n == NULL) return 0;
    for (i = 0; i < CAIRN_NODE_MAX_SESSIONS; i++)
        if (n->peers[i].state != CAIRN_ENGINE_EMPTY) count++;
    return count;
}

int cairn_engine_neighbour_count(const cairn_engine *n)
{
    if (n == NULL) return 0;
    return n->neighbours.count;
}

void cairn_engine_clear(cairn_engine *n)
{
    int i;

    if (n == NULL) return;
    cairn_identity_clear(&n->identity);
    for (i = 0; i < CAIRN_NODE_MAX_SESSIONS; i++)
        cairn_session_clear(&n->peers[i].session);
    cairn_memzero(n, sizeof *n);
}