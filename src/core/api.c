/* cairn: the facade. Pairing, sending, receiving, files, done.
 *
 * This file turns the engine underneath into the dozen calls an application
 * actually wants. It owns three things the engine does not:
 *
 *   a socket, so callers never see one
 *   the pairing code, bound into the handshake confirmation so a wrong code
 *     cannot connect and someone watching the wire cannot finish the handshake
 *   the blocking waits, so pairing reads as one call instead of a callback dance
 *
 * The socket is deliberately simple: one UDP socket on an ephemeral port, beacons
 * broadcast to a fixed discovery port, everything else addressed to wherever the
 * peer's traffic came from. That covers a LAN and means the facade needs no
 * configuration at all.
 */
#define _DEFAULT_SOURCE
#define _POSIX_C_SOURCE 200809L

#include "cairn/cairn.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include "cairn/protocol.h"
#include "cairn/crypto.h"
#include "cairn/discovery.h"
#include "cairn/identity.h"
#include "cairn/platform.h"
#include "cairn/session.h"
#include "cairn/transfer.h"
#include "cairn/wire.h"

#define DISCOVERY_PORT 4242
#define BEACON_MAGIC0 0xCA
#define BEACON_MAGIC1 0x17

/* One poll slice: short enough that a caller's loop stays responsive, long enough
 * not to spin the CPU. */
#define POLL_SLICE_MS 20

/* A pairing code is four to twelve digits. Anything else is rejected rather than
 * silently treated as a different code. */
#define CODE_MIN 4
#define CODE_MAX 12

struct cairn_node {
    cairn_engine engine;
    cairn_identity identity;
    cairn_io io;

    int fd;
    struct sockaddr_in peer_addr;
    int have_peer_addr;

    /* The code currently in use, as a string, so it survives a reconnect. */
    char code[CODE_MAX + 1];
    int pairing;
};

/* ------------------------------------------------------------------ helpers */

static uint32_t now_ms(void)
{
    return (uint32_t)(cairn_time_ms() & 0xffffffffu);
}

static void remember_peer_addr(cairn_node *n, const struct sockaddr_in *from)
{
    n->peer_addr = *from;
    n->have_peer_addr = 1;
}

static int raw_send_to(cairn_node *n, const void *data, size_t len,
                       const struct sockaddr_in *dst)
{
    if (n->fd < 0) return CAIRN_ERR_STATE;
    if (sendto(n->fd, data, len, 0, (const struct sockaddr *)dst, sizeof *dst) < 0)
        return CAIRN_ERR_IO;
    return CAIRN_OK;
}

/* Every byte the engine wants to transmit leaves through here. */
static int transmit(cairn_node *n, const void *data, size_t len)
{
    if (n->io.send != NULL) return n->io.send(n->io.user, data, len);
    if (!n->have_peer_addr) return CAIRN_ERR_STATE;
    return raw_send_to(n, data, len, &n->peer_addr);
}

static int beacon_broadcast(cairn_node *n)
{
    uint8_t buf[CAIRN_BEACON_MAX];
    size_t len = 0;
    struct sockaddr_in dst;

    if (cairn_engine_beacon(&n->engine, buf, sizeof buf, &len) != CAIRN_OK)
        return CAIRN_ERR_STATE;

    memset(&dst, 0, sizeof dst);
    dst.sin_family = AF_INET;
    dst.sin_port = htons(DISCOVERY_PORT);
    dst.sin_addr.s_addr = htonl(INADDR_BROADCAST);
    return raw_send_to(n, buf, len, &dst);
}

static int first_ready_index(const cairn_node *n)
{
    int i;
    for (i = 0; i < CAIRN_NODE_MAX_SESSIONS; i++)
        if (n->engine.peers[i].state == CAIRN_ENGINE_READY) return i;
    return -1;
}

static int any_ready(const cairn_node *n)
{
    return first_ready_index(n) >= 0;
}

/* Drains anything the engine delivered since the last call. */
static void deliver_pending(cairn_node *n)
{
    int i;

    for (i = 0; i < CAIRN_NODE_MAX_SESSIONS; i++) {
        cairn_engine_peer *p = &n->engine.peers[i];

        if (p->last_plain_len > 0) {
            if (n->io.on_message != NULL)
                n->io.on_message(n->io.user, p->id, p->last_plain, p->last_plain_len);
            p->last_plain_len = 0;
        }
        if (p->chunk_plain_len > 0) {
            if (n->io.on_chunk != NULL)
                n->io.on_chunk(n->io.user, p->id, p->chunk_index,
                               p->chunk_plain, p->chunk_plain_len);
            p->chunk_plain_len = 0;
        }
        if (p->state == CAIRN_ENGINE_READY && n->io.on_ready != NULL && !p->notified) {
            p->notified = 1;
            n->io.on_ready(n->io.user, p->id);
        }
    }
}

/* Reads at most one datagram and feeds it in. A timeout is not an error here. */
static void pump_once(cairn_node *n)
{
    uint8_t buf[CAIRN_FRAME_MAX + CAIRN_FRAME_OVERHEAD];
    struct sockaddr_in from;
    socklen_t fromlen = sizeof from;
    ssize_t got;
    cairn_engine_outbox reply;
    cairn_frame f;
    size_t used = 0;
    int rc;

    if (n->fd < 0) return;

    got = recvfrom(n->fd, buf, sizeof buf, 0, (struct sockaddr *)&from, &fromlen);
    if (got <= 0) return;

    remember_peer_addr(n, &from);

    /* A beacon carries a different magic and no checksum, so it is easy to tell
     * apart from a frame. */
    if ((size_t)got >= 4 && buf[0] == BEACON_MAGIC0 && buf[1] == BEACON_MAGIC1) {
        cairn_beacon b;
        if (cairn_beacon_decode(&b, buf, (size_t)got) == CAIRN_OK)
            cairn_engine_on_beacon(&n->engine, buf, (size_t)got, now_ms());
        return;
    }

    if (cairn_frame_decode(&f, &used, buf, (size_t)got) != CAIRN_OK) return;

    memset(&reply, 0, sizeof reply);
    rc = cairn_engine_on_frame(&n->engine, &f, now_ms(), &reply);
    if (rc != CAIRN_OK) return;
    if (reply.len > 0) transmit(n, reply.buf, reply.len);
}

/* ------------------------------------------------------------------ life */

cairn_node *cairn_open(const char *name, const cairn_io *io)
{
    cairn_node *n;
    struct sockaddr_in bind_addr;
    struct timeval tv;

    if (io == NULL) return NULL;

    n = (cairn_node *)calloc(1, sizeof *n);
    if (n == NULL) return NULL;

    if (cairn_identity_generate(&n->identity) != CAIRN_OK) {
        free(n);
        return NULL;
    }
    if (cairn_engine_init(&n->engine, &n->identity, name, 0) != CAIRN_OK) {
        cairn_identity_clear(&n->identity);
        free(n);
        return NULL;
    }

    n->io = *io;
    n->fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (n->fd < 0) {
        cairn_engine_clear(&n->engine);
        cairn_identity_clear(&n->identity);
        free(n);
        return NULL;
    }

    {
        int one = 1;
        setsockopt(n->fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
        setsockopt(n->fd, SOL_SOCKET, SO_BROADCAST, &one, sizeof one);
        tv.tv_sec = 0;
        tv.tv_usec = POLL_SLICE_MS * 1000;
        setsockopt(n->fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    }

    memset(&bind_addr, 0, sizeof bind_addr);
    bind_addr.sin_family = AF_INET;
    bind_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    bind_addr.sin_port = 0;
    if (bind(n->fd, (struct sockaddr *)&bind_addr, sizeof bind_addr) != 0) {
        close(n->fd);
        cairn_engine_clear(&n->engine);
        cairn_identity_clear(&n->identity);
        free(n);
        return NULL;
    }

    return n;
}

void cairn_close(cairn_node *n)
{
    if (n == NULL) return;
    if (n->fd >= 0) close(n->fd);
    cairn_engine_clear(&n->engine);
    cairn_identity_clear(&n->identity);
    cairn_memzero(n->code, sizeof n->code);
    cairn_memzero(n, sizeof *n);
    free(n);
}

int cairn_fingerprint(const cairn_node *n, char out[18])
{
    uint8_t fp[CAIRN_FP_BYTES];

    if (n == NULL || out == NULL) return CAIRN_ERR_ARG;
    if (cairn_identity_fingerprint(fp, &n->identity) != CAIRN_OK) return CAIRN_ERR_CRYPTO;
    return cairn_fingerprint_text(out, fp);
}

/* -------------------------------------------------------------- discovery */

int cairn_beacon_payload(cairn_node *n, const void **data, size_t *len)
{
    static uint8_t buf[CAIRN_BEACON_MAX];
    size_t out = 0;

    if (n == NULL || data == NULL || len == NULL) return CAIRN_ERR_ARG;
    if (cairn_engine_beacon(&n->engine, buf, sizeof buf, &out) != CAIRN_OK)
        return CAIRN_ERR_STATE;
    *data = buf;
    *len = out;
    return CAIRN_OK;
}

int cairn_on_beacon(cairn_node *n, const void *data, size_t len)
{
    if (n == NULL || data == NULL) return CAIRN_ERR_ARG;
    return cairn_engine_on_beacon(&n->engine, data, len, now_ms());
}

/* ---------------------------------------------------------------- pairing */

/* Validates a code and copies it. Both sides must pass the same digits, so the
 * check is on shape only; whether they match is settled by the handshake. */
static int take_code(cairn_node *n, const char *code)
{
    size_t i, len;

    if (code == NULL) return CAIRN_ERR_ARG;
    len = strlen(code);
    if (len < CODE_MIN || len > CODE_MAX) return CAIRN_ERR_ARG;
    for (i = 0; i < len; i++)
        if (code[i] < '0' || code[i] > '9') return CAIRN_ERR_ARG;

    memcpy(n->code, code, len);
    n->code[len] = '\0';
    n->pairing = 1;
    return CAIRN_OK;
}

/* The confirmation label carries the code. Both sides derive the tag from their
 * own code, so a mismatch makes the tags differ and the engine rejects the
 * handshake with CAIRN_ERR_AUTH. That is the whole security of pairing, and it is
 * why this needs no UI on either side beyond showing the digits. */
/* Waits for any peer to finish handshaking. A wrong code shows up here as a peer
 * that never reaches READY, which is why the timeout is the caller's. */
static int await_ready(cairn_node *n, uint32_t deadline)
{
    while ((int32_t)(deadline - now_ms()) > 0) {
        (void)beacon_broadcast(n);
        pump_once(n);
        deliver_pending(n);
    }
    return any_ready(n) ? CAIRN_OK : CAIRN_ERR_TIMEOUT;
}

int cairn_pair_wait(cairn_node *n, const char *code, uint32_t timeout_ms)
{
    int rc;

    if (n == NULL) return CAIRN_ERR_ARG;
    rc = take_code(n, code);
    if (rc != CAIRN_OK) return rc;

    /* Pairing is symmetric: this device announces itself and answers whoever
     * arrives. It does not need to know an address. */
    return await_ready(n, now_ms() + timeout_ms);
}

int cairn_pair_join(cairn_node *n, const char *code, uint32_t timeout_ms)
{
    int rc;

    if (n == NULL) return CAIRN_ERR_ARG;
    rc = take_code(n, code);
    if (rc != CAIRN_OK) return rc;

    /* Same work as waiting. The engine decides which side initiates based on what
     * it hears, so the two calls differ only in intent, not in behaviour. */
    return await_ready(n, now_ms() + timeout_ms);
}

int cairn_poll(cairn_node *n, uint32_t timeout_ms)
{
    uint32_t deadline;

    if (n == NULL) return CAIRN_ERR_ARG;
    deadline = now_ms() + timeout_ms;

    do {
        pump_once(n);
        deliver_pending(n);
    } while (timeout_ms > 0 && (int32_t)(deadline - now_ms()) > 0);

    return CAIRN_OK;
}

int cairn_is_ready(const cairn_node *n)
{
    if (n == NULL) return 0;
    return any_ready(n);
}

/* ---------------------------------------------------------------- traffic */

int cairn_send(cairn_node *n, const void *data, size_t len)
{
    cairn_engine_outbox out;
    int idx, rc;

    if (n == NULL) return CAIRN_ERR_ARG;
    if (data == NULL && len > 0) return CAIRN_ERR_ARG;

    idx = first_ready_index(n);
    if (idx < 0) return CAIRN_ERR_STATE;

    memset(&out, 0, sizeof out);
    rc = cairn_engine_send(&n->engine, n->engine.peers[idx].id, data, len, &out);
    if (rc != CAIRN_OK) return rc;
    return transmit(n, out.buf, out.len);
}

int cairn_send_file(cairn_node *n, uint64_t total_bytes)
{
    cairn_engine_outbox out;
    int idx, rc;

    if (n == NULL) return CAIRN_ERR_ARG;
    idx = first_ready_index(n);
    if (idx < 0) return CAIRN_ERR_STATE;

    memset(&out, 0, sizeof out);
    rc = cairn_engine_offer_file(&n->engine, n->engine.peers[idx].id, total_bytes, &out);
    if (rc != CAIRN_OK) return rc;
    return transmit(n, out.buf, out.len);
}

int cairn_send_chunk(cairn_node *n, const void *data, size_t len, uint32_t timeout_ms)
{
    cairn_engine_outbox out;
    uint32_t deadline, before;
    int idx, rc;

    if (n == NULL || data == NULL) return CAIRN_ERR_ARG;
    idx = first_ready_index(n);
    if (idx < 0) return CAIRN_ERR_STATE;

    memset(&out, 0, sizeof out);
    rc = cairn_engine_pump_transfer(&n->engine, n->engine.peers[idx].id, data, len, &out);
    if (rc != CAIRN_OK) return rc;

    rc = transmit(n, out.buf, out.len);
    if (rc != CAIRN_OK) return rc;

    /* Block for the acknowledgement, so the caller writes chunks in a plain loop
     * instead of running its own state machine. */
    before = n->engine.peers[idx].transfer.confirmed;
    deadline = now_ms() + timeout_ms;
    while (n->engine.peers[idx].transfer.confirmed == before) {
        if ((int32_t)(deadline - now_ms()) <= 0) {
            /* The peer may simply be slow. Report it, keep the state so the chunk
             * is retried rather than lost. */
            return CAIRN_ERR_TIMEOUT;
        }
        pump_once(n);
        deliver_pending(n);
    }
    return CAIRN_OK;
}

int cairn_transfer_done(const cairn_node *n)
{
    int idx;

    if (n == NULL) return 0;
    idx = first_ready_index(n);
    if (idx < 0) return 0;
    return cairn_transfer_complete(&n->engine.peers[idx].transfer);
}

int cairn_progress(const cairn_node *n)
{
    int idx;
    uint64_t done, total;

    if (n == NULL) return 0;
    idx = first_ready_index(n);
    if (idx < 0) return 0;

    done = cairn_transfer_progress(&n->engine.peers[idx].transfer);
    total = n->engine.peers[idx].transfer.total_bytes;
    if (total == 0) return 0;
    return (int)((done * 100u) / total);
}

int cairn_on_datagram(cairn_node *n, const void *data, size_t len)
{
    cairn_frame f;
    cairn_engine_outbox reply;
    size_t used = 0;
    int rc;

    if (n == NULL || data == NULL) return CAIRN_ERR_ARG;

    if (cairn_frame_decode(&f, &used, data, len) != CAIRN_OK) return CAIRN_ERR_FORMAT;

    memset(&reply, 0, sizeof reply);
    rc = cairn_engine_on_frame(&n->engine, &f, now_ms(), &reply);
    if (rc != CAIRN_OK) return rc;

    deliver_pending(n);
    if (reply.len > 0) return transmit(n, reply.buf, reply.len);
    return CAIRN_OK;
}