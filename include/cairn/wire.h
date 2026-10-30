/* cairn: wire framing.
 *
 * Every frame on every transport looks the same, which is what lets Bluetooth,
 * Wi-Fi Direct and plain sockets share one protocol:
 *
 *   magic[2] | version[1] | type[1] | length[4] | payload[length] | crc[4]
 *
 * Lengths are little endian. A frame larger than CAIRN_FRAME_MAX is refused
 * rather than truncated, and every length arithmetic is done in size_t with an
 * explicit overflow guard, because a frame decoder is the one place where an
 * attacker fully controls the numbers.
 */
#ifndef CAIRN_WIRE_H
#define CAIRN_WIRE_H

#include <stddef.h>
#include <stdint.h>

#include "cairn/cairn.h"

#ifdef __cplusplus
extern "C" {
#endif

#define CAIRN_FRAME_MAGIC0 0xC7
#define CAIRN_FRAME_MAGIC1 0x4E
#define CAIRN_FRAME_VERSION 1

/* Header plus trailer, without payload. */
#define CAIRN_FRAME_OVERHEAD (2 + 1 + 1 + 4 + 4)

/* Largest payload a single frame may carry. Bigger transfers are split by the
 * transport layer into chunks of at most this size. */
#define CAIRN_FRAME_MAX 65536

/* Largest chunk a fragment carries. Kept well under CAIRN_FRAME_MAX so a
 * fragment plus its own headers always fits one frame. */
#define CAIRN_CHUNK_BYTES 16384

typedef enum {
    CAIRN_FRAME_HELLO = 1,
    CAIRN_FRAME_ACCEPT = 2,
    CAIRN_FRAME_DATA = 3,
    CAIRN_FRAME_ACK = 4,
    CAIRN_FRAME_BYE = 5,
    CAIRN_FRAME_PING = 6,
    CAIRN_FRAME_PONG = 7,
    CAIRN_FRAME_XFER_META = 8,
    CAIRN_FRAME_XFER_CHUNK = 9,
    CAIRN_FRAME_XFER_DONE = 10,
    /* A beacon has room for an id and a fingerprint prefix, but the full public
     * key is over a kilobyte because of ML-KEM. This frame carries it, so two
     * devices that have only just heard each other can start a handshake. */
    CAIRN_FRAME_KEY = 11
} cairn_frame_type;

typedef struct {
    uint8_t type;
    const uint8_t *payload;
    size_t payloadlen;
} cairn_frame;

/* Bytes needed to encode a frame with this payload size. */
size_t cairn_frame_size(size_t payloadlen);

/* Encodes a frame. out must hold cairn_frame_size(payloadlen) bytes. Using the
 * same pointer for in and out is allowed only when they do not overlap. */
int cairn_frame_encode(uint8_t *out, size_t outcap, size_t *outlen,
                       uint8_t type, const void *payload, size_t payloadlen);

/* Decodes exactly one frame from buf. Returns CAIRN_ERR_FORMAT for a bad magic,
 * a bad version, an impossible length or a checksum mismatch. When the buffer
 * holds more than one frame, *consumed tells the caller where the next one
 * starts. */
int cairn_frame_decode(cairn_frame *out, size_t *consumed,
                       const void *buf, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* CAIRN_WIRE_H */