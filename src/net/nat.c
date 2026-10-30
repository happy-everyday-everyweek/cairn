/* cairn: STUN messages and the hole punching state machine. */
#include "cairn/nat.h"

#include <string.h>

#include "cairn/crypto.h"

#define DEFAULT_PUNCH_INTERVAL_MS 200u
#define DEFAULT_TIMEOUT_MS 5000u

static void put_u16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)v;
}

static void put_u32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

static uint16_t get_u16(const uint8_t *p)
{
    return (uint16_t)(((uint16_t)p[0] << 8) | p[1]);
}

static uint32_t get_u32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

int cairn_stun_build_request(uint8_t *out, size_t outcap, size_t *outlen,
                             const uint8_t transaction_id[12])
{
    if (out == NULL || outlen == NULL) return CAIRN_ERR_ARG;
    if (outcap < CAIRN_STUN_HEADER_BYTES) return CAIRN_ERR_BUFFER;

    put_u16(out + 0, CAIRN_STUN_BINDING_REQUEST);
    put_u16(out + 2, 0); /* no attributes */
    put_u32(out + 4, CAIRN_STUN_MAGIC);

    if (transaction_id != NULL) {
        memcpy(out + 8, transaction_id, 12);
    } else if (cairn_random_bytes(out + 8, 12) != CAIRN_OK) {
        return CAIRN_ERR_IO;
    }

    *outlen = CAIRN_STUN_HEADER_BYTES;
    return CAIRN_OK;
}

/* Reads one attribute body that carries an address, applying the XOR mask when
 * asked. Both families share the same first four bytes. */
static int read_address(const uint8_t *body, size_t bodylen, int xored,
                        uint32_t magic, cairn_endpoint *ep)
{
    uint16_t port;
    uint32_t ip;

    if (bodylen < 8) return CAIRN_ERR_FORMAT;
    if (body[1] != 0x01) return CAIRN_ERR_UNSUPPORTED; /* IPv4 only for now */

    port = get_u16(body + 2);
    ip = get_u32(body + 4);
    if (xored) {
        port = (uint16_t)(port ^ (uint16_t)(magic >> 16));
        ip ^= magic;
    }
    ep->port = port;
    ep->ip = ip;
    return CAIRN_OK;
}

int cairn_stun_parse_response(uint8_t transaction_id[12], cairn_endpoint *mapped,
                              const void *buf, size_t len)
{
    const uint8_t *p = (const uint8_t *)buf;
    uint16_t type, attrlen;
    size_t o;
    int have_xor = 0, have_plain = 0;
    cairn_endpoint xor_ep, plain_ep;
    uint32_t magic;

    if (buf == NULL || mapped == NULL) return CAIRN_ERR_ARG;
    if (len < CAIRN_STUN_HEADER_BYTES) return CAIRN_ERR_FORMAT;

    type = get_u16(p);
    /* A binding error must not be mistaken for a success. */
    if (type != CAIRN_STUN_BINDING_SUCCESS) return CAIRN_ERR_FORMAT;

    magic = get_u32(p + 4);
    if (magic != CAIRN_STUN_MAGIC) return CAIRN_ERR_FORMAT;

    attrlen = get_u16(p + 2);
    if ((size_t)attrlen + CAIRN_STUN_HEADER_BYTES > len) return CAIRN_ERR_FORMAT;

    if (transaction_id != NULL) memcpy(transaction_id, p + 8, 12);

    memset(&xor_ep, 0, sizeof xor_ep);
    memset(&plain_ep, 0, sizeof plain_ep);

    o = CAIRN_STUN_HEADER_BYTES;
    while (o + 4 <= CAIRN_STUN_HEADER_BYTES + (size_t)attrlen) {
        uint16_t atype = get_u16(p + o);
        uint16_t alen = get_u16(p + o + 2);
        size_t padded = (size_t)((alen + 3u) & ~3u);

        if (o + 4 + alen > len) return CAIRN_ERR_FORMAT;

        if (atype == CAIRN_STUN_ATTR_XOR_MAPPED_ADDRESS) {
            if (read_address(p + o + 4, alen, 1, magic, &xor_ep) == CAIRN_OK) have_xor = 1;
        } else if (atype == CAIRN_STUN_ATTR_MAPPED_ADDRESS) {
            if (read_address(p + o + 4, alen, 0, magic, &plain_ep) == CAIRN_OK)
                have_plain = 1;
        }
        o += 4 + padded;
    }

    /* Prefer the XOR form: the plain one is often rewritten by a middlebox. */
    if (have_xor) {
        *mapped = xor_ep;
        return CAIRN_OK;
    }
    if (have_plain) {
        *mapped = plain_ep;
        return CAIRN_OK;
    }
    return CAIRN_ERR_NOT_FOUND;
}

static int endpoint_equal(cairn_endpoint a, cairn_endpoint b)
{
    return a.ip == b.ip && a.port == b.port;
}

static int endpoint_known(cairn_endpoint e)
{
    return e.ip != 0 && e.port != 0;
}

int cairn_nat_begin(cairn_nat *n, cairn_endpoint local, cairn_endpoint external,
                    cairn_endpoint peer, uint32_t now_ms)
{
    if (n == NULL) return CAIRN_ERR_ARG;
    if (!endpoint_known(peer)) return CAIRN_ERR_ARG;

    memset(n, 0, sizeof *n);
    n->local = local;
    n->external = external;
    n->peer = peer;
    n->started_ms = now_ms;
    n->punch_interval_ms = DEFAULT_PUNCH_INTERVAL_MS;
    n->timeout_ms = DEFAULT_TIMEOUT_MS;
    /* Without a known external mapping there is nothing to punch toward yet. */
    n->state = endpoint_known(external) ? CAIRN_NAT_PUNCHING : CAIRN_NAT_DISCOVERING;
    return CAIRN_OK;
}

int cairn_nat_set_external(cairn_nat *n, cairn_endpoint external, uint32_t now_ms)
{
    if (n == NULL) return CAIRN_ERR_ARG;
    if (!endpoint_known(external)) return CAIRN_ERR_ARG;
    if (n->state == CAIRN_NAT_CONNECTED || n->state == CAIRN_NAT_RELAYING)
        return CAIRN_ERR_STATE;

    n->external = external;
    n->started_ms = now_ms;
    n->state = CAIRN_NAT_PUNCHING;
    return CAIRN_OK;
}

int cairn_nat_poll(cairn_nat *n, uint32_t now_ms, int *send_punch)
{
    if (n == NULL || send_punch == NULL) return CAIRN_ERR_ARG;
    *send_punch = 0;

    switch (n->state) {
    case CAIRN_NAT_CONNECTED:
    case CAIRN_NAT_RELAYING:
    case CAIRN_NAT_IDLE:
    case CAIRN_NAT_DISCOVERING:
    case CAIRN_NAT_FAILED:
        /* Discovering waits for the STUN answer, the rest are settled. */
        return CAIRN_OK;
    case CAIRN_NAT_PUNCHING:
    default:
        break;
    }

    /* Unsigned subtraction keeps the comparison correct across a clock wrap. */
    if ((uint32_t)(now_ms - n->started_ms) > n->timeout_ms) {
        n->state = CAIRN_NAT_FAILED;
        return CAIRN_OK;
    }

    if (n->attempts == 0 ||
        (uint32_t)(now_ms - n->last_punch_ms) >= n->punch_interval_ms) {
        n->last_punch_ms = now_ms;
        n->attempts++;
        *send_punch = 1;
    }
    return CAIRN_OK;
}

int cairn_nat_on_packet(cairn_nat *n, cairn_endpoint from, uint32_t now_ms)
{
    (void)now_ms;

    if (n == NULL) return CAIRN_ERR_ARG;
    if (n->state == CAIRN_NAT_CONNECTED) return CAIRN_OK;
    if (!endpoint_equal(from, n->peer)) return CAIRN_ERR_NOT_FOUND;

    /* Traffic from the exact peer address is the proof that both NATs opened. */
    n->state = CAIRN_NAT_CONNECTED;
    return CAIRN_OK;
}

int cairn_nat_fallback_relay(cairn_nat *n)
{
    if (n == NULL) return CAIRN_ERR_ARG;
    if (n->state == CAIRN_NAT_CONNECTED) return CAIRN_ERR_STATE;
    n->state = CAIRN_NAT_RELAYING;
    return CAIRN_OK;
}

cairn_nat_state cairn_nat_state_of(const cairn_nat *n)
{
    if (n == NULL) return CAIRN_NAT_FAILED;
    return n->state;
}

const char *cairn_nat_state_name(cairn_nat_state s)
{
    switch (s) {
    case CAIRN_NAT_IDLE: return "idle";
    case CAIRN_NAT_DISCOVERING: return "discovering";
    case CAIRN_NAT_PUNCHING: return "punching";
    case CAIRN_NAT_CONNECTED: return "connected";
    case CAIRN_NAT_RELAYING: return "relaying";
    case CAIRN_NAT_FAILED: return "failed";
    }
    return "unknown";
}