/* cairn: peer discovery.
 *
 * A beacon is the only thing that announces a device, so it has to be small,
 * self contained and impossible to confuse with anything else on the wire:
 *
 *   magic[2] | version[1] | flags[1] | id[16] | fingerprint_prefix[16]
 *   | port[2] | name_len[1] | name[name_len]
 *
 * The 16 byte truncated fingerprint in the beacon is what lets a peer skip a
 * device it has already paired with. The full 32 byte fingerprint is never
 * broadcast, only the prefix: enough to identify, not enough to be useful.
 *
 * Discovery itself is transport dependent: UDP multicast on a LAN, an
 * advertisement on BLE, a service record on Wi-Fi Direct. This module only owns
 * the payload and the neighbour table, so it is testable without a socket.
 */
#ifndef CAIRN_DISCOVERY_H
#define CAIRN_DISCOVERY_H

#include <stddef.h>
#include <stdint.h>

#include "cairn/cairn.h"
#include "cairn/identity.h"

#ifdef __cplusplus
extern "C" {
#endif

#define CAIRN_BEACON_MAGIC0 0xCA
#define CAIRN_BEACON_MAGIC1 0x17
#define CAIRN_BEACON_VERSION 1

/* Kept short so the whole beacon can fit one BLE advertisement. */
#define CAIRN_NAME_MAX 32

/* Capability bits: what this device is willing to do. */
#define CAIRN_CAP_TRANSFER 0x01u
#define CAIRN_CAP_CHAT 0x02u
#define CAIRN_CAP_RELAY 0x04u

/* Worst case beacon size, including the name. */
#define CAIRN_BEACON_MAX (2 + 1 + 1 + CAIRN_ID_BYTES + 16 + 2 + 1 + CAIRN_NAME_MAX)

#define CAIRN_NEIGHBOURS_MAX 32

typedef struct {
    uint8_t id[CAIRN_ID_BYTES];
    uint8_t fp_prefix[16];
    uint16_t port;
    uint8_t capabilities;
    char name[CAIRN_NAME_MAX + 1];
} cairn_beacon;

typedef struct {
    cairn_beacon entries[CAIRN_NEIGHBOURS_MAX];
    uint32_t last_seen_ms[CAIRN_NEIGHBOURS_MAX];
    int count;
} cairn_neighbours;

/* Encodes a beacon. out must hold CAIRN_BEACON_MAX bytes. */
int cairn_beacon_encode(uint8_t *out, size_t outcap, size_t *outlen,
                        const cairn_beacon *b);

/* Decodes a beacon. A short, oversize or malformed buffer is refused. */
int cairn_beacon_decode(cairn_beacon *b, const void *buf, size_t len);

/* Fills a beacon from an identity and a display name. The name is truncated to
 * CAIRN_NAME_MAX bytes rather than rejected, because a host name is not ours to
 * validate. */
int cairn_beacon_from_identity(cairn_beacon *b, const cairn_identity *id,
                               const char *name, uint16_t port,
                               uint8_t capabilities);

/* Inserts or refreshes a neighbour. Returns CAIRN_ERR_MEMORY when the table is
 * full and the peer is new. */
int cairn_neighbours_add(cairn_neighbours *n, const cairn_beacon *b, uint32_t now_ms);

/* Looks a neighbour up by id. */
int cairn_neighbours_find(const cairn_neighbours *n, const uint8_t id[CAIRN_ID_BYTES]);

/* Drops entries older than ttl_ms. */
int cairn_neighbours_expire(cairn_neighbours *n, uint32_t now_ms, uint32_t ttl_ms);

void cairn_neighbours_clear(cairn_neighbours *n);

#ifdef __cplusplus
}
#endif

#endif /* CAIRN_DISCOVERY_H */