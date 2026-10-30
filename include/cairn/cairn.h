/* cairn: the facade a normal application uses.
 *
 * This header is the whole public surface for the common case. A dozen calls cover
 * pairing, sending, receiving, file transfer and shutdown, and none of them
 * mention frames, sessions, keys or sockets.
 *
 *   cairn_node *n = cairn_open("phone", &io);
 *   cairn_pair_wait(n, "123456", 30000);   // the other side joins
 *   cairn_send(n, "hello", 5);
 *   cairn_poll(n, 100);
 *   cairn_close(n);
 *
 * Pairing is symmetric. One device calls cairn_pair_wait with the code on screen,
 * the other calls cairn_pair_join with the same code, and both return CAIRN_OK or
 * an error. Neither side needs to know which one is the client.
 *
 * The lower layers in cairn/session.h, cairn/wire.h and friends are still here,
 * unmoved, for an application that wants to drive the protocol itself. They are
 * not required by anything in this header.
 */
#ifndef CAIRN_H
#define CAIRN_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define CAIRN_VERSION_MAJOR 0
#define CAIRN_VERSION_MINOR 2

/* Status codes. Zero is success; every failure is negative and stable, so an
 * application can switch on it and print cairn_strerror. */
enum cairn_status {
    CAIRN_OK = 0,
    CAIRN_ERR_ARG = -1,          /* a pointer or a length was wrong */
    CAIRN_ERR_MEMORY = -2,       /* a fixed table was full */
    CAIRN_ERR_UNIMPLEMENTED = -3,
    CAIRN_ERR_CRYPTO = -4,       /* a primitive refused the input */
    CAIRN_ERR_FORMAT = -5,       /* bytes on the wire did not parse */
    CAIRN_ERR_AUTH = -6,         /* wrong key, wrong code or tampering */
    CAIRN_ERR_REPLAY = -7,       /* this message was already accepted */
    CAIRN_ERR_BUFFER = -8,       /* the caller's buffer was too small */
    CAIRN_ERR_TIMEOUT = -9,      /* the wait expired */
    CAIRN_ERR_NOT_FOUND = -10,   /* no such peer, or nothing to read */
    CAIRN_ERR_STATE = -11,       /* called in the wrong order */
    CAIRN_ERR_IO = -12,          /* the transport refused */
    CAIRN_ERR_UNSUPPORTED = -13  /* this build or target cannot do that */
};

/* Human readable form of a status code. Never returns NULL. */
const char *cairn_strerror(int status);

/* Zeroes memory in a way the compiler may not optimise away. */
void cairn_memzero(void *p, size_t n);

/* Constant time comparison: 1 when equal, 0 otherwise. */
int cairn_memeq(const void *a, const void *b, size_t n);

#define CAIRN_ID_BYTES 16

/* ------------------------------------------------------------------ events */

/* Bytes arriving from the remote side. data is only valid during the call. */
typedef void (*cairn_message_cb)(void *user, const uint8_t peer[CAIRN_ID_BYTES],
                                 const void *data, size_t len);

/* A file chunk. index counts from zero; the last chunk may be short. */
typedef void (*cairn_chunk_cb)(void *user, const uint8_t peer[CAIRN_ID_BYTES],
                               uint32_t index, const void *data, size_t len);

/* Pairing finished, so a conversation may start. */
typedef void (*cairn_ready_cb)(void *user, const uint8_t peer[CAIRN_ID_BYTES]);

typedef struct {
    cairn_message_cb on_message;
    cairn_chunk_cb on_chunk;
    cairn_ready_cb on_ready;
    /* Optional. Every byte to transmit goes here; return 0 on success. When it is
     * NULL the node does not send anything by itself, which is what the CLI uses
     * when it wants to own the socket. */
    int (*send)(void *user, const void *data, size_t len);
    void *user;
} cairn_io;

typedef struct cairn_node cairn_node;

/* ------------------------------------------------------------------ life */

/* Creates a node. name is the display name peers see, and may be NULL. The io
 * callbacks are copied, so the struct may live on the caller's stack. */
cairn_node *cairn_open(const char *name, const cairn_io *io);

/* Frees a node and wipes its keys. NULL is allowed. */
void cairn_close(cairn_node *n);

/* This device's fingerprint as six hex pairs, for a human to read out. */
int cairn_fingerprint(const cairn_node *n, char out[18]);

/* -------------------------------------------------------------- discovery */

/* The beacon to broadcast or advertise. The pointer stays valid until the next
 * call on this node, so copy it if it must outlive that. */
int cairn_beacon_payload(cairn_node *n, const void **data, size_t *len);

/* Feeds a datagram that might be a beacon. Returns CAIRN_OK when it was one, so a
 * caller can tell "new peer nearby" from "not my traffic". */
int cairn_on_beacon(cairn_node *n, const void *data, size_t len);

/* ---------------------------------------------------------------- pairing */

/* Waits for a peer that will use this code. Blocks up to timeout_ms and returns
 * CAIRN_OK once a session is established, CAIRN_ERR_TIMEOUT otherwise.
 *
 * The code is four to twelve digits. */
int cairn_pair_wait(cairn_node *n, const char *code, uint32_t timeout_ms);

/* Joins a peer waiting on the same code. Blocks up to timeout_ms. */
int cairn_pair_join(cairn_node *n, const char *code, uint32_t timeout_ms);

/* Drives the state machine without blocking. Call this from the application's own
 * loop when it cannot afford a blocking call. */
int cairn_poll(cairn_node *n, uint32_t timeout_ms);

/* True once at least one peer is paired and the channel is usable. */
int cairn_is_ready(const cairn_node *n);

/* ---------------------------------------------------------------- traffic */

/* Sends bytes to the first paired peer. CAIRN_ERR_STATE before pairing. */
int cairn_send(cairn_node *n, const void *data, size_t len);

/* Offers a file of total_bytes. The application then feeds chunks with
 * cairn_send_chunk until cairn_transfer_done returns true. */
int cairn_send_file(cairn_node *n, uint64_t total_bytes);

/* Sends one chunk of a file previously offered. Blocks until it is acknowledged,
 * or until timeout_ms passes. */
int cairn_send_chunk(cairn_node *n, const void *data, size_t len, uint32_t timeout_ms);

/* True when every chunk of the current file has been acknowledged. */
int cairn_transfer_done(const cairn_node *n);

/* Fraction of the current file already acknowledged, 0 to 100. */
int cairn_progress(const cairn_node *n);

/* --------------------------------------------------------------- advanced */

/* Feeds one raw datagram from the transport. This is what cairn_poll uses
 * internally; call it directly only when the application owns the socket. */
int cairn_on_datagram(cairn_node *n, const void *data, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* CAIRN_H */