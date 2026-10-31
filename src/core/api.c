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
/* The socket layer is the one place in this file that differs by platform, so it is
 * isolated here rather than sprinkled through the code. Windows needs WinSock and its
 * own close; everything POSIX shaped shares the rest. */
#ifdef _WIN32
#  define WIN32_LEAN_AND_MEAN
#  include <winsock2.h>
#  include <ws2tcpip.h>
#  define cairn_closesocket closesocket
#  define cairn_last_socket_error() WSAGetLastError()
/* MSVC has no ssize_t, and recvfrom returns int there. */
typedef int cairn_sock_result;
#else
#  define _DEFAULT_SOURCE
#  define _POSIX_C_SOURCE 200809L
#  include <arpa/inet.h>
#  include <netinet/in.h>
#  include <sys/socket.h>
#  include <sys/time.h>
#  include <unistd.h>
#  define cairn_closesocket close
typedef ssize_t cairn_sock_result;
#endif

#include "cairn/cairn.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

    int fd;          /* data: ephemeral port */
    int beacon_fd;   /* discovery: fixed port, shared */
    struct sockaddr_in peer_addr;    /* where frames go */
    int have_peer_addr;
    struct sockaddr_in beacon_addr;  /* where a reply beacon goes */
    int have_beacon_addr;

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

/* Sends our beacon out.
 *
 * Three destinations, each covering a case the others cannot:
 *
 *   the subnet broadcast, so a device we have never met can find us. This is the
 *   normal discovery path on a LAN.
 *   the discovery address we last heard a beacon from, so a node whose discovery
 *   socket landed on an ephemeral port still learns about us. Two instances on one
 *   machine end up in exactly that situation, because only one of them can own the
 *   fixed port.
 *   the peer's data port once a conversation exists, which is the path that survives
 *   a network that filters broadcast.
 */
static void beacon_broadcast(cairn_node *n)
{
    uint8_t buf[CAIRN_BEACON_MAX];
    size_t len = 0;
    struct sockaddr_in dst;

    if (cairn_engine_beacon(&n->engine, buf, sizeof buf, &len) != CAIRN_OK) return;

    if (n->beacon_fd >= 0) {
        memset(&dst, 0, sizeof dst);
        dst.sin_family = AF_INET;
        dst.sin_port = htons(DISCOVERY_PORT);

        /* The subnet, for devices we have never met. */
        dst.sin_addr.s_addr = htonl(INADDR_BROADCAST);
        (void)sendto(n->beacon_fd, buf, len, 0, (struct sockaddr *)&dst, sizeof dst);

        /* Loopback, for another instance on this machine. This is a unicast to the
         * discovery port, which is deterministic precisely because only one node may
         * own that port; relying on broadcast being looped back to local sockets is
         * what made same-host pairing work on one machine and not another. */
        dst.sin_addr.s_addr = htonl(0x7f000001u);
        (void)sendto(n->beacon_fd, buf, len, 0, (struct sockaddr *)&dst, sizeof dst);
    }

    if (n->have_beacon_addr)
        (void)sendto(n->beacon_fd, buf, len, 0,
                     (struct sockaddr *)&n->beacon_addr, sizeof n->beacon_addr);

    if (n->have_peer_addr) (void)raw_send_to(n, buf, len, &n->peer_addr);
}

/* Records where a beacon came from. Two addresses, because they mean different things:
 * the source is where a reply beacon goes, and the advertised port is where frames go.
 * Conflating them was a bug that pointed every KEY frame at the discovery port. */
static void remember_beacon_sender(cairn_node *n, const struct sockaddr_in *from,
                                   const cairn_beacon *b)
{
    n->beacon_addr = *from;
    n->have_beacon_addr = 1;

    n->peer_addr = *from;
    n->peer_addr.sin_port = htons(b->port);
    n->have_peer_addr = 1;
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

/* Receive timeout, in milliseconds. The units differ by platform: POSIX wants a
 * struct timeval, Winsock wants a DWORD of milliseconds. */
static void set_recv_timeout(int fd, uint32_t ms)
{
#ifdef _WIN32
    DWORD value = (DWORD)ms;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (const char *)&value, sizeof value);
#else
    struct timeval tv;
    tv.tv_sec = (time_t)(ms / 1000u);
    tv.tv_usec = (suseconds_t)((ms % 1000u) * 1000u);
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof tv);
#endif
}

/* Reads at most one datagram and feeds it in. A timeout is not an error here. */
static void pump_once(cairn_node *n)
{
    uint8_t buf[CAIRN_FRAME_MAX + CAIRN_FRAME_OVERHEAD];
    struct sockaddr_in from;
    socklen_t fromlen = sizeof from;
    cairn_sock_result got;
    cairn_engine_outbox reply;
    cairn_frame f;
    size_t used = 0;
    int pass;

    if (n->fd < 0) return;

    for (pass = 0; pass < 8; pass++) {
        int handled = 0;

        if (n->beacon_fd >= 0) {
            got = recvfrom(n->beacon_fd, buf, sizeof buf, 0,
                           (struct sockaddr *)&from, &fromlen);
            if (got > 0) {
                cairn_beacon b;
                handled = 1;

                if (cairn_beacon_decode(&b, buf, (size_t)got) == CAIRN_OK &&
                    memcmp(b.id, n->engine.beacon.id, CAIRN_ID_BYTES) != 0) {
                    remember_beacon_sender(n, &from, &b);
                    cairn_engine_on_beacon(&n->engine, buf, (size_t)got, now_ms());
                }
                /* A beacon from ourselves is dropped whole, address included. Recording
                 * our own sender address here pointed every later KEY and HELLO frame at
                 * our own socket, which is why two nodes on one machine sometimes ended
                 * up with a peer slot for themselves and never completed a handshake. */
            }
        }

        got = recvfrom(n->fd, buf, sizeof buf, 0,
                       (struct sockaddr *)&from, &fromlen);
        if (got > 0) {
            handled = 1;

            /* A beacon reaches this socket too, because we broadcast from it. When that
             * happens the sender port is the peer's discovery socket, not the data port
             * we must answer on, so the advertised port has to replace it. Remembering
             * the raw sender address here was a real bug: KEY and HELLO frames then went
             * to port 4242, and pairing worked only when a beacon happened to arrive on
             * the other socket instead. */
            if ((size_t)got >= 4 && buf[0] == BEACON_MAGIC0 && buf[1] == BEACON_MAGIC1) {
                cairn_beacon b;
                /* Self beacons are dropped before the address is recorded, for the
                 * reason given above. */
                if (cairn_beacon_decode(&b, buf, (size_t)got) == CAIRN_OK &&
                    memcmp(b.id, n->engine.beacon.id, CAIRN_ID_BYTES) != 0) {
                    remember_beacon_sender(n, &from, &b);
                    cairn_engine_on_beacon(&n->engine, buf, (size_t)got, now_ms());
                }
            } else {
                remember_peer_addr(n, &from);
            }

            if (cairn_frame_decode(&f, &used, buf, (size_t)got) == CAIRN_OK) {
                memset(&reply, 0, sizeof reply);
                if (cairn_engine_on_frame(&n->engine, &f, now_ms(), &reply) == CAIRN_OK &&
                    reply.len > 0)
                    transmit(n, reply.buf, reply.len);
            }
        }

        if (!handled) break;
    }
}

/* ------------------------------------------------------------------ life */

cairn_node *cairn_open(const char *name, const cairn_io *io)
{
    cairn_node *n;
    struct sockaddr_in bind_addr;

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
    n->fd = -1;
    n->beacon_fd = -1;

#ifdef _WIN32
    {
        WSADATA wsa;
        if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
            free(n);
            return NULL;
        }
    }
#endif

    /* Two sockets, because beacons and data have different addressing needs.
     *
     *   fd        an ephemeral port. Everything after discovery goes here, addressed
     *             to whoever we last heard from.
     *   beacon_fd the fixed discovery port, shared with SO_REUSEPORT so several
     *             instances on one machine can all receive beacons.
     *
     * Without the second socket a beacon addressed to the discovery port lands nowhere,
     * which is exactly the bug this arrangement exists to prevent.
     */
    n->fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (n->fd < 0) goto fail;
    n->beacon_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (n->beacon_fd < 0) goto fail;

    {
        int one = 1;

        setsockopt(n->fd, SOL_SOCKET, SO_REUSEADDR, (const char *)&one, sizeof one);
        setsockopt(n->fd, SOL_SOCKET, SO_BROADCAST, (const char *)&one, sizeof one);
        set_recv_timeout(n->fd, POLL_SLICE_MS);

        /* The discovery socket deliberately does not set SO_REUSEPORT. Sharing the port
         * between two nodes makes delivery of a given packet depend on which socket the
         * kernel picks, and on some platforms a broadcast then reaches only one of them.
         * One owner plus unicast replies is deterministic on every platform. */
        setsockopt(n->beacon_fd, SOL_SOCKET, SO_BROADCAST, (const char *)&one, sizeof one);
        set_recv_timeout(n->beacon_fd, POLL_SLICE_MS);
    }

    memset(&bind_addr, 0, sizeof bind_addr);
    bind_addr.sin_family = AF_INET;
    bind_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    bind_addr.sin_port = 0;
    if (bind(n->fd, (struct sockaddr *)&bind_addr, sizeof bind_addr) != 0) goto fail;

    /* The discovery socket needs the fixed port. If it is taken by a process that did
     * not set SO_REUSEPORT, discovery still works one way: we keep broadcasting and
     * answering whatever arrives on the data socket.
     */
    bind_addr.sin_port = htons(DISCOVERY_PORT);
    if (bind(n->beacon_fd, (struct sockaddr *)&bind_addr, sizeof bind_addr) != 0) {
        /* Somebody else on this machine already owns the discovery port. Fall back to
         * an ephemeral one: the node that does own it will answer our broadcast with a
         * unicast beacon, and from then on both sides know where to send. Trying to
         * share the port instead would make delivery a lottery, which is exactly the
         * failure this avoids. */
        bind_addr.sin_port = 0;
        if (bind(n->beacon_fd, (struct sockaddr *)&bind_addr, sizeof bind_addr) != 0) {
            cairn_closesocket(n->beacon_fd);
            n->beacon_fd = -1;
        }
    }

    /* The beacon must advertise the data port, not the discovery port: that is where a
     * peer should send HELLO once it has seen us. */
    {
        struct sockaddr_in self;
        socklen_t selflen = sizeof self;
        if (getsockname(n->fd, (struct sockaddr *)&self, &selflen) == 0) {
            n->engine.beacon.port = ntohs(self.sin_port);
            n->engine.port = ntohs(self.sin_port);
        }
    }

    return n;

fail:
    if (n->fd >= 0) cairn_closesocket(n->fd);
    if (n->beacon_fd >= 0) cairn_closesocket(n->beacon_fd);
    cairn_engine_clear(&n->engine);
    cairn_identity_clear(&n->identity);
    free(n);
    return NULL;
}

void cairn_close(cairn_node *n)
{
    if (n == NULL) return;
    if (n->fd >= 0) cairn_closesocket(n->fd);
    if (n->beacon_fd >= 0) cairn_closesocket(n->beacon_fd);
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

/* Pairs this node with whoever else is using the same code.
 *
 * The sequence is the same one the engine tests drive by hand, only here the socket
 * and the clock do the driving:
 *
 *   1. broadcast a beacon so the other side learns we exist
 *   2. on seeing a peer, answer with our full public key (a beacon is too small)
 *   3. once we hold the peer's key, the side with the lower code digit value sends
 *      HELLO, and the other waits for it, so both never initiate at once
 *   4. the handshake's confirmation tags carry the code, so a mismatch fails here
 *
 * Step 3 is the part that makes two identical calls on two devices converge: both
 * compute the same comparison from the same digits and pick opposite roles without
 * exchanging another message.
 */
static int pair_loop(cairn_node *n, uint32_t deadline)
{
    uint32_t last_beacon = 0;
    uint32_t last_key = 0;
    uint32_t last_hello = 0;
    uint32_t last_accept = 0;

    while ((int32_t)(deadline - now_ms()) > 0) {
        cairn_engine_outbox out;
        int i;

        /* Beacons go out about three times a second rather than every pass.
         * Broadcasting on every iteration floods the peer's receive queue with beacons
         * and starves the KEY and HELLO frames that actually matter. */
        if (last_beacon == 0 || (uint32_t)(now_ms() - last_beacon) > 300) {
            beacon_broadcast(n);
            last_beacon = now_ms();
        }

        pump_once(n);
        deliver_pending(n);

        if (any_ready(n)) return CAIRN_OK;

        /* Everything below is decided from the state that exists right now, with no
         * counters carried between passes. That matters: an earlier version tracked
         * "already announced" and "already started", so one lost datagram left those
         * flags set and the attempt could never be retried. Pairing then worked only
         * when the first try happened to land, which is worse than never working
         * because it looks like a timing flake.
         */
        for (i = 0; i < CAIRN_NODE_MAX_SESSIONS; i++) {
            cairn_engine_peer *p = &n->engine.peers[i];
            cairn_pair_view view;

            /* The decision is a pure function so it can be checked without a socket;
             * this loop only supplies the facts and performs the action. */
            view.peer_state = (int)p->state;
            view.has_key = p->has_key;
            view.we_initiate = memcmp(n->engine.beacon.id, p->id, CAIRN_ID_BYTES) < 0;
            view.key_due = (last_key == 0 || (uint32_t)(now_ms() - last_key) > 400);
            view.hello_due = (last_hello == 0 || (uint32_t)(now_ms() - last_hello) > 600);
            /* The responder retransmits sooner, because its reply is the one the
             * initiator cannot ask for again on its own. */
            view.accept_due = (last_accept == 0 || (uint32_t)(now_ms() - last_accept) > 200);

            switch (cairn_pair_next(&view)) {
            case CAIRN_PAIR_SEND_KEY:
                memset(&out, 0, sizeof out);
                if (cairn_engine_announce_key(&n->engine, p->id, &out) == CAIRN_OK &&
                    out.len > 0)
                    (void)transmit(n, out.buf, out.len);
                last_key = now_ms();
                break;

            case CAIRN_PAIR_SEND_HELLO:
                memset(&out, 0, sizeof out);
                if (cairn_engine_connect(&n->engine, p->id, now_ms(), &out) == CAIRN_OK)
                    (void)transmit(n, out.buf, out.len);
                last_hello = now_ms();
                break;

            case CAIRN_PAIR_SEND_ACCEPT:
                memset(&out, 0, sizeof out);
                if (cairn_engine_accept(&n->engine, p->id, now_ms(), &out) == CAIRN_OK &&
                    out.len > 0)
                    (void)transmit(n, out.buf, out.len);
                last_accept = now_ms();
                break;

            case CAIRN_PAIR_IDLE:
            default:
                break;
            }
        }
    }

    return any_ready(n) ? CAIRN_OK : CAIRN_ERR_TIMEOUT;
}

int cairn_pair_wait(cairn_node *n, const char *code, uint32_t timeout_ms)
{
    int rc;

    if (n == NULL) return CAIRN_ERR_ARG;
    rc = take_code(n, code);
    if (rc != CAIRN_OK) return rc;

    /* The code must reach the engine, which puts it into the handshake labels. Without
     * this the tags are computed from the bare phase name and any code would connect. */
    rc = cairn_engine_set_code(&n->engine, n->code);
    if (rc != CAIRN_OK) return rc;

    return pair_loop(n, now_ms() + timeout_ms);
}

int cairn_pair_join(cairn_node *n, const char *code, uint32_t timeout_ms)
{
    /* Deliberately identical to waiting. Which side sends HELLO is decided by the
     * code comparison inside pair_loop, not by who called which function, so two
     * applications never have to agree on roles. */
    return cairn_pair_wait(n, code, timeout_ms);
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
