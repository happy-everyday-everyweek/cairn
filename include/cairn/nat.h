/* cairn: NAT traversal.
 *
 * Two devices behind different NATs cannot reach each other by address alone, so
 * this module does the three things that make direct connections possible:
 *
 *   STUN binding request   learn the external address of a UDP socket
 *   hole punching          both sides send to the other's external address at
 *                          the same time, so each NAT sees an outbound packet
 *                          and opens the mapping
 *   relay fallback         when punching fails, use a third party to forward
 *
 * The state machine is deterministic and driven entirely by the caller's clock,
 * which is what makes it testable in a loopback environment with a simulated
 * NAT. No test contacts a public STUN server: the request bytes are checked
 * against the RFC 5389 layout and the response parser is fed hand built packets.
 */
#ifndef CAIRN_NAT_H
#define CAIRN_NAT_H

#include <stddef.h>
#include <stdint.h>

#include "cairn/cairn.h"

#ifdef __cplusplus
extern "C" {
#endif

#define CAIRN_STUN_MAGIC 0x2112A442u
#define CAIRN_STUN_HEADER_BYTES 20
#define CAIRN_STUN_MAX_BYTES 512

/* STUN message types we care about. */
#define CAIRN_STUN_BINDING_REQUEST 0x0001
#define CAIRN_STUN_BINDING_SUCCESS 0x0101
#define CAIRN_STUN_BINDING_ERROR 0x0111

/* Attributes. */
#define CAIRN_STUN_ATTR_MAPPED_ADDRESS 0x0001
#define CAIRN_STUN_ATTR_XOR_MAPPED_ADDRESS 0x0020
#define CAIRN_STUN_ATTR_SOFTWARE 0x8022

typedef enum {
    CAIRN_NAT_IDLE = 0,
    CAIRN_NAT_DISCOVERING = 1,
    CAIRN_NAT_PUNCHING = 2,
    CAIRN_NAT_CONNECTED = 3,
    CAIRN_NAT_RELAYING = 4,
    CAIRN_NAT_FAILED = 5
} cairn_nat_state;

typedef struct {
    uint32_t ip;      /* host byte order */
    uint16_t port;    /* host byte order */
} cairn_endpoint;

typedef struct {
    cairn_endpoint local;
    cairn_endpoint external;
    cairn_endpoint peer;
    uint32_t started_ms;
    uint32_t last_punch_ms;
    uint32_t punch_interval_ms;
    uint32_t timeout_ms;
    uint32_t attempts;
    cairn_nat_state state;
} cairn_nat;

/* Builds a STUN binding request. out must hold CAIRN_STUN_MAX_BYTES. The
 * transaction id is filled with random bytes unless provided. */
int cairn_stun_build_request(uint8_t *out, size_t outcap, size_t *outlen,
                             const uint8_t transaction_id[12]);

/* Parses a binding response and extracts the mapped address. Accepts both
 * MAPPED-ADDRESS and XOR-MAPPED-ADDRESS, preferring the latter. */
int cairn_stun_parse_response(uint8_t transaction_id[12], cairn_endpoint *mapped,
                              const void *buf, size_t len);

/* Starts punching toward the peer's external address. */
int cairn_nat_begin(cairn_nat *n, cairn_endpoint local, cairn_endpoint external,
                    cairn_endpoint peer, uint32_t now_ms);

/* Reports that the external address was learned; moves to punching. */
int cairn_nat_set_external(cairn_nat *n, cairn_endpoint external, uint32_t now_ms);

/* Tells the caller whether a punch packet is due now. Keeps the schedule inside
 * the module so the caller never invents its own timing. */
int cairn_nat_poll(cairn_nat *n, uint32_t now_ms, int *send_punch);

/* Any inbound packet from the peer's address confirms the hole. */
int cairn_nat_on_packet(cairn_nat *n, cairn_endpoint from, uint32_t now_ms);

/* Gives up punching and moves to relay, which the caller then has to provide. */
int cairn_nat_fallback_relay(cairn_nat *n);

cairn_nat_state cairn_nat_state_of(const cairn_nat *n);

const char *cairn_nat_state_name(cairn_nat_state s);

#ifdef __cplusplus
}
#endif

#endif /* CAIRN_NAT_H */