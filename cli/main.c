/* cairn CLI: demonstrates the whole stack over real UDP sockets.
 *
 * The library owns no sockets on purpose, so the CLI owns them. It parses
 * arguments, binds a socket, reads files, and prints results. Everything
 * cryptographic or protocol shaped is a library call.
 *
 *   cairn key                     print this device's fingerprint
 *   cairn selftest                two nodes talking over loopback UDP
 *   cairn listen [port]           answer handshakes and print what arrives
 *   cairn send <ip> <port> <text> send one message
 *   cairn put  <ip> <port> <file> send a file, chunk by chunk, with acks
 *
 * The exchange has three steps because a beacon is far too small for a full
 * public key, which carries an ML-KEM key of over a kilobyte:
 *
 *   beacon (id + fingerprint prefix)   tells you a device exists
 *   KEY frame (full public key)        lets a handshake begin
 *   HELLO / ACCEPT / ACK               proves both sides derived the same root
 */
#define _DEFAULT_SOURCE
#define _POSIX_C_SOURCE 200809L

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#include "cairn/cairn.h"
#include "cairn/discovery.h"
#include "cairn/identity.h"
#include "cairn/node.h"
#include "cairn/platform.h"
#include "cairn/transfer.h"
#include "cairn/wire.h"

#define DEFAULT_PORT 9000
#define STEP_MS 100
#define STEP_LIMIT 120

static int g_verbose;

static void usage(const char *argv0)
{
    fprintf(stderr,
            "cairn %d.%d\n"
            "  %s key                       print this device's fingerprint\n"
            "  %s selftest                  two nodes over loopback UDP\n"
            "  %s listen [port]\n"
            "  %s send <ip> <port> <message>\n"
            "  %s put  <ip> <port> <file>\n",
            CAIRN_VERSION_MAJOR, CAIRN_VERSION_MINOR,
            argv0, argv0, argv0, argv0, argv0);
}

static int bind_udp(uint16_t port)
{
    struct sockaddr_in addr;
    int fd, one = 1;

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return -1;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one) != 0) {
        close(fd);
        return -1;
    }

    memset(&addr, 0, sizeof addr);
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(port);
    if (bind(fd, (struct sockaddr *)&addr, sizeof addr) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

static int send_to(int fd, const char *ip, uint16_t port, const void *data, size_t len)
{
    struct sockaddr_in addr;

    memset(&addr, 0, sizeof addr);
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if (inet_pton(AF_INET, ip, &addr.sin_addr) != 1) return -1;
    return sendto(fd, data, len, 0, (struct sockaddr *)&addr, sizeof addr) < 0 ? -1 : 0;
}

static int flush_outbox(int fd, const char *ip, uint16_t port, const cairn_outbox *out)
{
    if (out->len == 0) return 0;
    if (g_verbose)
        fprintf(stderr, "-> %s:%u frame %u, %zu bytes\n", ip, port, out->type, out->len);
    return send_to(fd, ip, port, out->buf, out->len);
}

/* One datagram through the decoder and then the node, answering if required. */
static int pump_inbound(cairn_node *node, const void *data, size_t len, int fd,
                        const char *ip, uint16_t port)
{
    cairn_frame f;
    cairn_outbox reply;
    size_t used = 0;
    int rc;

    rc = cairn_frame_decode(&f, &used, data, len);
    if (rc != CAIRN_OK) {
        if (g_verbose)
            fprintf(stderr, "drop malformed datagram (%s)\n", cairn_status_string(rc));
        return rc;
    }

    memset(&reply, 0, sizeof reply);
    rc = cairn_node_on_frame(node, &f, (uint32_t)cairn_time_ms(), &reply);
    if (rc != CAIRN_OK) {
        if (g_verbose)
            fprintf(stderr, "frame %u rejected (%s)\n", f.type, cairn_status_string(rc));
        return rc;
    }
    if (reply.len > 0) flush_outbox(fd, ip, port, &reply);
    return CAIRN_OK;
}

/* Receive for at most timeout_ms, pumping everything into the node. */
static void drain(cairn_node *node, int fd, const char *ip, uint16_t port,
                  uint32_t timeout_ms)
{
    uint32_t start = (uint32_t)cairn_time_ms();

    while ((uint32_t)(cairn_time_ms() - start) <= timeout_ms) {
        uint8_t buf[CAIRN_FRAME_MAX + CAIRN_FRAME_OVERHEAD];
        struct sockaddr_in from;
        socklen_t fromlen = sizeof from;
        ssize_t n = recvfrom(fd, buf, sizeof buf, MSG_DONTWAIT,
                             (struct sockaddr *)&from, &fromlen);

        if (n > 0)
            pump_inbound(node, buf, (size_t)n, fd, ip, port);
        else
            cairn_sleep_ms(STEP_MS / 5);
    }
}

/* The demo identity lives in $HOME/.cairn-identity and holds only the Ed25519
 * seed. Regenerating the rest keeps the file tiny; a real deployment would store
 * the whole identity. */
static int load_or_create_identity(cairn_identity *id, const char *path)
{
    FILE *fp;
    uint8_t seed[32];
    int rc;

    fp = fopen(path, "rb");
    if (fp != NULL) {
        size_t got = fread(seed, 1, sizeof seed, fp);
        fclose(fp);
        if (got == sizeof seed) {
            rc = cairn_ed25519_keypair_from_seed(id->ed_pub, id->ed_sec, seed);
            if (rc != CAIRN_OK) return rc;
            /* The X25519 and ML-KEM halves are not derived from the seed here,
             * so regenerate them; the demo prints its fingerprint per run. */
            return cairn_identity_generate(id);
        }
    }

    rc = cairn_identity_generate(id);
    if (rc != CAIRN_OK) return rc;

    fp = fopen(path, "wb");
    if (fp != NULL) {
        fwrite(id->ed_sec, 1, 32, fp);
        fclose(fp);
    }
    return CAIRN_OK;
}

static const char *identity_path(void)
{
    static char buf[512];
    const char *home = getenv("HOME");

    if (home == NULL) home = ".";
    snprintf(buf, sizeof buf, "%s/.cairn-identity", home);
    return buf;
}

/* Two nodes, one process, one real socket. The library is deliberately I/O free,
 * so this is what wiring it to a transport looks like: take the outbox bytes, put
 * them on the wire, read them back, feed them in. */
static int cmd_selftest(void)
{
    cairn_identity ida, idb;
    cairn_pubkey pka, pkb;
    cairn_node a, b;
    cairn_outbox out;
    cairn_frame f;
    size_t used = 0;
    int fd, rc, ready_a, ready_b;
    uint16_t loop_port = 0;

    if (cairn_identity_generate(&ida) != CAIRN_OK) return 1;
    if (cairn_identity_generate(&idb) != CAIRN_OK) return 1;
    cairn_identity_pubkey(&ida, &pka);
    cairn_identity_pubkey(&idb, &pkb);

    if (cairn_node_init(&a, &ida, "alice", 0) != CAIRN_OK) return 1;
    if (cairn_node_init(&b, &idb, "bob", 0) != CAIRN_OK) return 1;
    cairn_node_add_peer(&a, &pkb, "bob");
    cairn_node_add_peer(&b, &pka, "alice");

    fd = bind_udp(0);
    if (fd < 0) {
        fprintf(stderr, "socket: %s\n", strerror(errno));
        cairn_node_clear(&a);
        cairn_node_clear(&b);
        return 1;
    }

    /* A datagram socket that was never connected cannot use send(); it has to be
     * addressed. Remember the bound port so the loopback can talk to itself. */
    {
        struct sockaddr_in self;
        socklen_t selflen = sizeof self;
        if (getsockname(fd, (struct sockaddr *)&self, &selflen) != 0) {
            fprintf(stderr, "getsockname: %s\n", strerror(errno));
            close(fd);
            cairn_node_clear(&a);
            cairn_node_clear(&b);
            return 1;
        }
        loop_port = ntohs(self.sin_port);
    }

    memset(&out, 0, sizeof out);
    rc = cairn_node_connect(&a, pkb.id, (uint32_t)cairn_time_ms(), &out);
    if (rc != CAIRN_OK) {
        fprintf(stderr, "connect: %s\n", cairn_status_string(rc));
        close(fd);
        cairn_node_clear(&a);
        cairn_node_clear(&b);
        return 1;
    }

    /* Three round trips: HELLO to bob, ACCEPT to alice, ACK to bob. Every frame goes
     * through the socket so the byte level path is exercised, not bypassed. */
    {
        cairn_outbox to_b, from_b;
        cairn_frame f;
        size_t used = 0;
        uint8_t buf[2 * (CAIRN_FRAME_MAX + CAIRN_FRAME_OVERHEAD)];
        size_t have = 0;

        /* 1. alice's HELLO travels through the socket and lands on bob. */
        if (out.len == 0) goto done;
        if (send_to(fd, "127.0.0.1", loop_port, out.buf, out.len) < 0) goto done;
        {
            ssize_t n = recv(fd, buf, out.len, 0);
            if (n != (ssize_t)out.len || memcmp(buf, out.buf, out.len) != 0) goto done;
        }
        if (cairn_frame_decode(&f, &used, out.buf, out.len) != CAIRN_OK) goto done;

        memset(&from_b, 0, sizeof from_b);
        rc = cairn_node_on_frame(&b, &f, (uint32_t)cairn_time_ms(), &from_b);
        if (rc != CAIRN_OK) {
            fprintf(stderr, "bob rejected HELLO: %s\n", cairn_status_string(rc));
            goto done;
        }
        if (g_verbose) fprintf(stderr, "step 1 ok, bob reply %zu bytes\n", from_b.len);

        /* 2. bob's ACCEPT travels back to alice, which also verifies the tag. */
        if (from_b.len == 0) goto done;
        if (send_to(fd, "127.0.0.1", loop_port, from_b.buf, from_b.len) < 0) goto done;
        {
            ssize_t n = recv(fd, buf, from_b.len, 0);
            if (n != (ssize_t)from_b.len || memcmp(buf, from_b.buf, from_b.len) != 0)
                goto done;
        }
        if (cairn_frame_decode(&f, &used, from_b.buf, from_b.len) != CAIRN_OK) goto done;

        memset(&to_b, 0, sizeof to_b);
        rc = cairn_node_on_frame(&a, &f, (uint32_t)cairn_time_ms(), &to_b);
        if (rc != CAIRN_OK) {
            fprintf(stderr, "alice rejected ACCEPT: %s\n", cairn_status_string(rc));
            goto done;
        }

        /* 3. alice's confirmation closes the loop on bob's side. */
        if (to_b.len == 0) goto done;
        if (send_to(fd, "127.0.0.1", loop_port, to_b.buf, to_b.len) < 0) goto done;
        {
            ssize_t n = recv(fd, buf, to_b.len, 0);
            if (n != (ssize_t)to_b.len || memcmp(buf, to_b.buf, to_b.len) != 0) goto done;
        }
        if (cairn_frame_decode(&f, &used, to_b.buf, to_b.len) != CAIRN_OK) goto done;

        memset(&from_b, 0, sizeof from_b);
        rc = cairn_node_on_frame(&b, &f, (uint32_t)cairn_time_ms(), &from_b);
        if (rc != CAIRN_OK) {
            fprintf(stderr, "bob rejected ACK: %s\n", cairn_status_string(rc));
            goto done;
        }
    }

done:

    ready_a = cairn_node_peer_state(&a, pkb.id) == CAIRN_PEER_READY;
    ready_b = cairn_node_peer_state(&b, pka.id) == CAIRN_PEER_READY;

    memset(&out, 0, sizeof out);
    rc = cairn_node_send(&a, pkb.id, "selftest", 8, &out);
    if (rc == CAIRN_OK) {
        cairn_frame mf;
        cairn_outbox none;
        size_t got = 0;
        memset(&none, 0, sizeof none);
        if (cairn_frame_decode(&mf, &got, out.buf, out.len) == CAIRN_OK)
            cairn_node_on_frame(&b, &mf, (uint32_t)cairn_time_ms(), &none);
    }

    printf("handshake: alice=%s bob=%s\n",
           ready_a ? "ready" : "not ready", ready_b ? "ready" : "not ready");
    printf("send: %s\n", cairn_status_string(rc));
    if (rc == CAIRN_OK)
        printf("delivered: %zu bytes, \"%.*s\"\n", b.peers[0].last_plain_len,
               (int)b.peers[0].last_plain_len, b.peers[0].last_plain);

    close(fd);
    cairn_node_clear(&a);
    cairn_node_clear(&b);
    cairn_identity_clear(&ida);
    cairn_identity_clear(&idb);
    return (ready_a && ready_b && rc == CAIRN_OK) ? 0 : 1;
}

static int cmd_key(void)
{
    cairn_identity id;
    uint8_t fp[CAIRN_FP_BYTES];
    char text[18];
    int rc;

    rc = load_or_create_identity(&id, identity_path());
    if (rc != CAIRN_OK) {
        fprintf(stderr, "identity: %s\n", cairn_status_string(rc));
        return 1;
    }
    cairn_identity_fingerprint(fp, &id);
    cairn_fingerprint_text(text, fp);
    printf("%s\n", text);
    cairn_identity_clear(&id);
    return 0;
}

/* Announces us and waits for the peer's full public key in a KEY frame. */
static int introduce(cairn_node *node, int fd, const char *ip, uint16_t port,
                     uint8_t peer_id[CAIRN_ID_BYTES])
{
    cairn_outbox out;
    uint32_t start = (uint32_t)cairn_time_ms();
    int i, rc;

    memset(&out, 0, sizeof out);
    rc = cairn_node_announce_key(node, NULL, &out);
    if (rc != CAIRN_OK) return rc;
    flush_outbox(fd, ip, port, &out);

    while ((uint32_t)(cairn_time_ms() - start) < STEP_LIMIT * STEP_MS) {
        uint8_t buf[CAIRN_FRAME_MAX + CAIRN_FRAME_OVERHEAD];
        struct sockaddr_in from;
        socklen_t fromlen = sizeof from;
        ssize_t n = recvfrom(fd, buf, sizeof buf, MSG_DONTWAIT,
                             (struct sockaddr *)&from, &fromlen);

        if (n > 0) {
            pump_inbound(node, buf, (size_t)n, fd, ip, port);
            for (i = 0; i < CAIRN_NODE_MAX_SESSIONS; i++)
                if (node->peers[i].state == CAIRN_PEER_KNOWN) {
                    memcpy(peer_id, node->peers[i].id, CAIRN_ID_BYTES);
                    return CAIRN_OK;
                }
        } else {
            cairn_sleep_ms(STEP_MS / 2);
        }
    }
    return CAIRN_ERR_TIMEOUT;
}

static int cmd_send_or_put(const char *ip, uint16_t port, const char *what, int is_file)
{
    cairn_node node;
    cairn_identity id;
    cairn_outbox out;
    uint8_t peer_id[CAIRN_ID_BYTES];
    int fd, rc;

    rc = load_or_create_identity(&id, identity_path());
    if (rc != CAIRN_OK) {
        fprintf(stderr, "identity: %s\n", cairn_status_string(rc));
        return 1;
    }
    rc = cairn_node_init(&node, &id, "cli", DEFAULT_PORT);
    if (rc != CAIRN_OK) {
        fprintf(stderr, "node: %s\n", cairn_status_string(rc));
        return 1;
    }

    fd = bind_udp(0);
    if (fd < 0) {
        fprintf(stderr, "socket: %s\n", strerror(errno));
        cairn_node_clear(&node);
        return 1;
    }

    if (introduce(&node, fd, ip, port, peer_id) != CAIRN_OK) {
        fprintf(stderr, "no key from %s:%u (is something listening?)\n", ip, port);
        close(fd);
        cairn_node_clear(&node);
        return 1;
    }
    printf("peer key learned\n");

    memset(&out, 0, sizeof out);
    rc = cairn_node_connect(&node, peer_id, (uint32_t)cairn_time_ms(), &out);
    if (rc != CAIRN_OK) {
        fprintf(stderr, "connect: %s\n", cairn_status_string(rc));
        close(fd);
        cairn_node_clear(&node);
        return 1;
    }
    flush_outbox(fd, ip, port, &out);

    drain(&node, fd, ip, port, STEP_LIMIT * STEP_MS);
    if (cairn_node_peer_state(&node, peer_id) != CAIRN_PEER_READY) {
        fprintf(stderr, "handshake did not finish\n");
        close(fd);
        cairn_node_clear(&node);
        return 1;
    }
    printf("channel ready\n");

    if (!is_file) {
        memset(&out, 0, sizeof out);
        rc = cairn_node_send(&node, peer_id, what, strlen(what), &out);
        if (rc != CAIRN_OK) {
            fprintf(stderr, "send: %s\n", cairn_status_string(rc));
        } else {
            flush_outbox(fd, ip, port, &out);
            printf("sent %zu bytes\n", strlen(what));
        }
    } else {
        struct stat st;
        FILE *fp;
        uint8_t chunk[CAIRN_CHUNK_BYTES];
        int guard;

        if (stat(what, &st) != 0 || (fp = fopen(what, "rb")) == NULL) {
            fprintf(stderr, "%s: %s\n", what, strerror(errno));
            close(fd);
            cairn_node_clear(&node);
            return 1;
        }

        memset(&out, 0, sizeof out);
        rc = cairn_node_offer_file(&node, peer_id, (uint64_t)st.st_size, &out);
        if (rc == CAIRN_OK) flush_outbox(fd, ip, port, &out);

        for (guard = 0; guard < 4096; guard++) {
            uint32_t index = 0;
            size_t want = 0;

            if (cairn_transfer_next_chunk(&node.peers[0].transfer, &index, &want)
                != CAIRN_OK)
                break;

            fseek(fp, (long)((uint64_t)index * CAIRN_CHUNK_BYTES), SEEK_SET);
            if (fread(chunk, 1, want, fp) != want) break;

            memset(&out, 0, sizeof out);
            rc = cairn_node_pump_transfer(&node, peer_id, chunk, want, &out);
            if (rc != CAIRN_OK) {
                fprintf(stderr, "chunk %u: %s\n", index, cairn_status_string(rc));
                break;
            }
            flush_outbox(fd, ip, port, &out);
            drain(&node, fd, ip, port, 2000);
        }
        fclose(fp);
        printf("%s\n", cairn_transfer_complete(&node.peers[0].transfer)
                           ? "file sent" : "file incomplete");
    }

    close(fd);
    cairn_node_clear(&node);
    cairn_identity_clear(&id);
    return 0;
}

static int cmd_listen(uint16_t port)
{
    cairn_node node;
    cairn_identity id;
    uint8_t beacon[CAIRN_BEACON_MAX];
    size_t beaconlen = 0;
    int fd, rc;

    rc = load_or_create_identity(&id, identity_path());
    if (rc != CAIRN_OK) {
        fprintf(stderr, "identity: %s\n", cairn_status_string(rc));
        return 1;
    }
    rc = cairn_node_init(&node, &id, "cli", port);
    if (rc != CAIRN_OK) {
        fprintf(stderr, "node: %s\n", cairn_status_string(rc));
        return 1;
    }
    cairn_node_beacon(&node, beacon, sizeof beacon, &beaconlen);

    fd = bind_udp(port);
    if (fd < 0) {
        fprintf(stderr, "socket: %s\n", strerror(errno));
        cairn_node_clear(&node);
        return 1;
    }

    printf("listening on udp %u\n", port);
    fflush(stdout);

    for (;;) {
        uint8_t buf[CAIRN_FRAME_MAX + CAIRN_FRAME_OVERHEAD];
        struct sockaddr_in from;
        socklen_t fromlen = sizeof from;
        ssize_t n = recvfrom(fd, buf, sizeof buf, 0, (struct sockaddr *)&from, &fromlen);
        char ip[INET_ADDRSTRLEN];
        cairn_beacon b;
        cairn_frame f;
        cairn_outbox reply;
        size_t used = 0;

        if (n <= 0) continue;
        inet_ntop(AF_INET, &from.sin_addr, ip, sizeof ip);

        /* A bare beacon is news, and it asks for our key in return. */
        if (cairn_beacon_decode(&b, buf, (size_t)n) == CAIRN_OK) {
            cairn_node_on_beacon(&node, buf, (size_t)n, (uint32_t)cairn_time_ms());
            printf("beacon from %s at %s\n", b.name[0] ? b.name : "unnamed", ip);
            memset(&reply, 0, sizeof reply);
            cairn_node_announce_key(&node, b.id, &reply);
            flush_outbox(fd, ip, ntohs(from.sin_port), &reply);
            continue;
        }

        if (cairn_frame_decode(&f, &used, buf, (size_t)n) != CAIRN_OK) {
            if (g_verbose) fprintf(stderr, "drop malformed datagram from %s\n", ip);
            continue;
        }

        memset(&reply, 0, sizeof reply);
        rc = cairn_node_on_frame(&node, &f, (uint32_t)cairn_time_ms(), &reply);
        if (rc != CAIRN_OK) {
            if (g_verbose)
                fprintf(stderr, "frame %u: %s\n", f.type, cairn_status_string(rc));
            continue;
        }
        flush_outbox(fd, ip, ntohs(from.sin_port), &reply);

        if (f.type == CAIRN_FRAME_DATA) {
            int i;
            for (i = 0; i < CAIRN_NODE_MAX_SESSIONS; i++) {
                if (node.peers[i].state == CAIRN_PEER_READY &&
                    node.peers[i].last_plain_len > 0) {
                    printf("message: %.*s\n", (int)node.peers[i].last_plain_len,
                           node.peers[i].last_plain);
                    fflush(stdout);
                    node.peers[i].last_plain_len = 0;
                }
            }
        } else if (f.type == CAIRN_FRAME_XFER_META) {
            printf("incoming file declared\n");
            fflush(stdout);
        } else if (f.type == CAIRN_FRAME_XFER_CHUNK) {
            int i;
            for (i = 0; i < CAIRN_NODE_MAX_SESSIONS; i++) {
                if (node.peers[i].state == CAIRN_PEER_READY) {
                    printf("chunk %u/%u\n", node.peers[i].transfer.confirmed,
                           node.peers[i].transfer.chunk_count);
                    fflush(stdout);
                }
            }
        }
    }
}

int main(int argc, char **argv)
{
    uint16_t port;

    if (argc < 2) {
        usage(argv[0]);
        return 1;
    }
    g_verbose = getenv("CAIRN_VERBOSE") != NULL;

    if (strcmp(argv[1], "key") == 0) return cmd_key();
    if (strcmp(argv[1], "selftest") == 0) return cmd_selftest();

    if (strcmp(argv[1], "listen") == 0) {
        port = argc >= 3 ? (uint16_t)atoi(argv[2]) : DEFAULT_PORT;
        return cmd_listen(port);
    }

    if (strcmp(argv[1], "send") == 0) {
        if (argc < 5) {
            usage(argv[0]);
            return 1;
        }
        return cmd_send_or_put(argv[2], (uint16_t)atoi(argv[3]), argv[4], 0);
    }

    if (strcmp(argv[1], "put") == 0) {
        if (argc < 5) {
            usage(argv[0]);
            return 1;
        }
        return cmd_send_or_put(argv[2], (uint16_t)atoi(argv[3]), argv[4], 1);
    }

    usage(argv[0]);
    return 1;
}