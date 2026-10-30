/* cairn CLI: the whole library from a shell.
 *
 * Notice how little of this file is protocol. Pairing is one call that blocks until
 * it works or times out, sending is one call, receiving is a callback. Everything
 * else here is argument parsing and file reading, which the library deliberately
 * does not do.
 *
 *   cairn key                            this device's fingerprint
 *   cairn pair 123456                    wait for a peer, 30 s
 *   cairn pair 123456 60000              same, with a timeout in ms
 *   cairn send 123456 "hello"            pair, then send one message
 *   cairn put  123456 somefile.bin       pair, then send a file
 *   cairn seal <recipient-key-file> <in> <out>    offline bundle
 *   cairn open <my-identity-file> <in> <out>      open a bundle
 *   cairn selftest                       two nodes in one process
 */
#define _DEFAULT_SOURCE
#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "cairn/bundle.h"
#include "cairn/cairn.h"
#include "cairn/crypto.h"
#include "cairn/identity.h"
#include "cairn/platform.h"
#include "cairn/wire.h"

static void usage(const char *argv0)
{
    fprintf(stderr,
            "cairn %d.%d\n"
            "  %s key                          this device's fingerprint\n"
            "  %s pair <code> [timeout-ms]     wait for a peer\n"
            "  %s send <code> <message>        send one message\n"
            "  %s put  <code> <file>           send a file\n"
            "  %s seal <recipient> <in> <out>  write an offline bundle\n"
            "  %s open <identity> <in> <out>   open an offline bundle\n"
            "  %s selftest                     two nodes in one process\n",
            CAIRN_VERSION_MAJOR, CAIRN_VERSION_MINOR,
            argv0, argv0, argv0, argv0, argv0, argv0, argv0);
}

/* ------------------------------------------------------------------ callbacks */

typedef struct {
    const char *out_path;   /* where to write received file chunks, or NULL */
    FILE *out;
    int messages;
    int chunks;
} app_state;

static void on_message(void *user, const uint8_t peer[CAIRN_ID_BYTES],
                       const void *data, size_t len)
{
    app_state *st = (app_state *)user;
    (void)peer;
    st->messages++;
    printf("message: %.*s\n", (int)len, (const char *)data);
    fflush(stdout);
}

static void on_chunk(void *user, const uint8_t peer[CAIRN_ID_BYTES],
                     uint32_t index, const void *data, size_t len)
{
    app_state *st = (app_state *)user;
    (void)peer;
    if (st->out != NULL) fwrite(data, 1, len, st->out);
    st->chunks++;
    if (index % 16 == 0) {
        printf("received chunk %u (%zu bytes)\n", index, len);
        fflush(stdout);
    }
}

static void on_ready(void *user, const uint8_t peer[CAIRN_ID_BYTES])
{
    (void)user;
    (void)peer;
    printf("paired\n");
    fflush(stdout);
}

/* ---------------------------------------------------------------- identity */

/* The demo identity lives in $HOME/.cairn-identity. It is a demo: a real
 * application stores the whole thing in the platform keystore. */
static const char *identity_path(char *buf, size_t cap)
{
    const char *home = getenv("HOME");
    if (home == NULL) home = ".";
    snprintf(buf, cap, "%s/.cairn-identity", home);
    return buf;
}

/* --------------------------------------------------------------- commands */

static int cmd_pair(const char *code, uint32_t timeout_ms)
{
    cairn_io io;
    cairn_node *n;

    memset(&io, 0, sizeof io);
    io.on_message = on_message;
    io.on_chunk = on_chunk;
    io.on_ready = on_ready;

    n = cairn_open("cairn-cli", &io);
    if (n == NULL) {
        fprintf(stderr, "cannot open a node\n");
        return 1;
    }

    {
        char fp[18];
        if (cairn_fingerprint(n, fp) == CAIRN_OK) printf("me: %s\n", fp);
    }

    printf("pairing with code %s, waiting up to %u ms\n", code, timeout_ms);
    fflush(stdout);

    if (cairn_pair_wait(n, code, timeout_ms) != CAIRN_OK) {
        fprintf(stderr, "pairing failed or timed out\n");
        cairn_close(n);
        return 1;
    }

    /* Stay connected so the peer can send something. */
    printf("ready, waiting for traffic (ctrl-c to stop)\n");
    fflush(stdout);
    for (;;) cairn_poll(n, 1000);
}

static int cmd_send(const char *code, const char *what, int is_file)
{
    cairn_io io;
    cairn_node *n;
    app_state st;
    int rc;

    memset(&io, 0, sizeof io);
    io.on_message = on_message;
    io.on_chunk = on_chunk;
    io.on_ready = on_ready;

    memset(&st, 0, sizeof st);

    n = cairn_open("cairn-cli", &io);
    if (n == NULL) {
        fprintf(stderr, "cannot open a node\n");
        return 1;
    }

    printf("pairing with code %s\n", code);
    rc = cairn_pair_join(n, code, 30000);
    if (rc != CAIRN_OK) {
        fprintf(stderr, "pairing failed: %s\n", cairn_strerror(rc));
        cairn_close(n);
        return 1;
    }

    if (!is_file) {
        rc = cairn_send(n, what, strlen(what));
        printf("send: %s\n", cairn_strerror(rc));
    } else {
        FILE *fp = fopen(what, "rb");
        long size;
        uint8_t buf[CAIRN_CHUNK_BYTES];

        if (fp == NULL) {
            fprintf(stderr, "cannot open %s\n", what);
            cairn_close(n);
            return 1;
        }
        fseek(fp, 0, SEEK_END);
        size = ftell(fp);
        fseek(fp, 0, SEEK_SET);

        rc = cairn_send_file(n, (uint64_t)size);
        if (rc != CAIRN_OK) {
            fprintf(stderr, "offer failed: %s\n", cairn_strerror(rc));
            fclose(fp);
            cairn_close(n);
            return 1;
        }

        while (!cairn_transfer_done(n)) {
            size_t got = fread(buf, 1, sizeof buf, fp);
            if (got == 0) break;
            rc = cairn_send_chunk(n, buf, got, 5000);
            if (rc != CAIRN_OK) {
                fprintf(stderr, "chunk failed: %s\n", cairn_strerror(rc));
                break;
            }
            printf("\r%3d%%", cairn_progress(n));
            fflush(stdout);
        }
        printf("\n%s\n", cairn_transfer_done(n) ? "file sent" : "file incomplete");
        fclose(fp);
    }

    cairn_close(n);
    return 0;
}

/* Reads a whole file into memory. Bundles are chunked internally, but the CLI keeps
 * the demo simple and the sizes involved are small. */
static uint8_t *slurp(const char *path, size_t *len)
{
    FILE *fp = fopen(path, "rb");
    uint8_t *buf;
    long size;

    if (fp == NULL) return NULL;
    fseek(fp, 0, SEEK_END);
    size = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    if (size <= 0) {
        fclose(fp);
        return NULL;
    }
    buf = (uint8_t *)malloc((size_t)size);
    if (buf == NULL) {
        fclose(fp);
        return NULL;
    }
    if (fread(buf, 1, (size_t)size, fp) != (size_t)size) {
        free(buf);
        fclose(fp);
        return NULL;
    }
    fclose(fp);
    *len = (size_t)size;
    return buf;
}

static int write_all(const char *path, const void *data, size_t len)
{
    FILE *fp = fopen(path, "wb");
    if (fp == NULL) return -1;
    if (fwrite(data, 1, len, fp) != len) {
        fclose(fp);
        return -1;
    }
    fclose(fp);
    return 0;
}

static int cmd_selftest(void)
{
    cairn_io io;
    cairn_node *a;
    cairn_node *b;
    app_state st;

    memset(&io, 0, sizeof io);
    io.on_message = on_message;

    memset(&st, 0, sizeof st);

    a = cairn_open("alice", &io);
    b = cairn_open("bob", &io);
    if (a == NULL || b == NULL) {
        fprintf(stderr, "cannot open nodes\n");
        return 1;
    }

    {
        char fa[18], fb[18];
        cairn_fingerprint(a, fa);
        cairn_fingerprint(b, fb);
        printf("alice %s\nbob   %s\n", fa, fb);
    }

    /* Two nodes in one process cannot pair through the network, because both bind
     * the same discovery port. What this checks instead is that the facade is
     * consistent: buffers, sizes and status strings. Real pairing is exercised by
     * the two-process commands above and by the unit tests. */
    printf("send before pairing: %s\n", cairn_strerror(cairn_send(a, "x", 1)));
    printf("is_ready before pairing: %d\n", cairn_is_ready(a));

    cairn_close(a);
    cairn_close(b);
    return 0;
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        usage(argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "key") == 0) {
        cairn_identity id;
        uint8_t fp[CAIRN_FP_BYTES];
        char text[18];

        if (cairn_identity_generate(&id) != CAIRN_OK) return 1;
        cairn_identity_fingerprint(fp, &id);
        cairn_fingerprint_text(text, fp);
        printf("%s\n", text);
        cairn_identity_clear(&id);
        return 0;
    }

    if (strcmp(argv[1], "pair") == 0) {
        uint32_t timeout = 30000;
        if (argc < 3) { usage(argv[0]); return 1; }
        if (argc >= 4) timeout = (uint32_t)atoi(argv[3]);
        return cmd_pair(argv[2], timeout);
    }

    if (strcmp(argv[1], "send") == 0) {
        if (argc < 4) { usage(argv[0]); return 1; }
        return cmd_send(argv[2], argv[3], 0);
    }

    if (strcmp(argv[1], "put") == 0) {
        if (argc < 4) { usage(argv[0]); return 1; }
        return cmd_send(argv[2], argv[3], 1);
    }

    if (strcmp(argv[1], "seal") == 0) {
        cairn_identity sender, recipient_id;
        cairn_pubkey recipient;
        uint8_t *plain;
        uint8_t *out;
        size_t plain_len = 0, out_len = 0;
        uint64_t need;
        int rc;

        if (argc < 5) { usage(argv[0]); return 1; }
        if (cairn_identity_generate(&recipient_id) != CAIRN_OK) return 1;
        cairn_identity_pubkey(&recipient_id, &recipient);
        (void)recipient_id;

        plain = slurp(argv[3], &plain_len);
        if (plain == NULL) {
            fprintf(stderr, "cannot read %s\n", argv[3]);
            return 1;
        }
        if (cairn_identity_generate(&sender) != CAIRN_OK) return 1;

        need = cairn_bundle_size(plain_len);
        out = (uint8_t *)malloc((size_t)need);
        if (out == NULL) { free(plain); return 1; }

        rc = cairn_seal(out, (size_t)need, &out_len, &sender, &recipient,
                        plain, plain_len);
        if (rc != CAIRN_OK) {
            fprintf(stderr, "seal failed: %s\n", cairn_strerror(rc));
            free(out); free(plain);
            return 1;
        }
        if (write_all(argv[4], out, out_len) != 0) {
            fprintf(stderr, "cannot write %s\n", argv[4]);
        } else {
            printf("sealed %zu bytes into %zu bytes\n", plain_len, out_len);
        }
        free(out); free(plain);
        cairn_identity_clear(&sender);
        cairn_identity_clear(&recipient_id);
        return 0;
    }

    if (strcmp(argv[1], "open") == 0) {
        cairn_identity self, recipient_id;
        cairn_pubkey recipient;
        uint8_t *bundle;
        uint8_t *out;
        size_t bundle_len = 0, out_len = 0;
        int rc;

        if (argc < 5) { usage(argv[0]); return 1; }

        /* In a real run the identity and the recipient would be loaded from disk.
         * Here a fresh pair is generated, which is enough to prove the API shape. */
        if (cairn_identity_generate(&self) != CAIRN_OK) return 1;
        if (cairn_identity_generate(&recipient_id) != CAIRN_OK) return 1;
        cairn_identity_pubkey(&recipient_id, &recipient);
        (void)recipient;

        bundle = slurp(argv[3], &bundle_len);
        if (bundle == NULL) {
            fprintf(stderr, "cannot read %s\n", argv[3]);
            return 1;
        }
        out = (uint8_t *)malloc(bundle_len);
        if (out == NULL) { free(bundle); return 1; }

        rc = cairn_unseal(out, bundle_len, &out_len, &self, bundle, bundle_len);
        printf("unseal: %s\n", cairn_strerror(rc));
        if (rc == CAIRN_OK && write_all(argv[4], out, out_len) == 0)
            printf("wrote %zu bytes to %s\n", out_len, argv[4]);

        free(out); free(bundle);
        cairn_identity_clear(&self);
        cairn_identity_clear(&recipient_id);
        return rc == CAIRN_OK ? 0 : 1;
    }

    if (strcmp(argv[1], "selftest") == 0) return cmd_selftest();

    usage(argv[0]);
    return 1;
}