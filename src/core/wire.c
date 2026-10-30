/* cairn: frame encoding and decoding. */
#include "cairn/wire.h"

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

size_t cairn_frame_size(size_t payloadlen)
{
    return CAIRN_FRAME_OVERHEAD + payloadlen;
}

/* CRC-32 (IEEE 802.3), reflected, computed bitwise so no table is needed. */
static uint32_t crc32(const uint8_t *data, size_t len)
{
    uint32_t crc = 0xffffffffu;
    size_t i;
    int bit;

    for (i = 0; i < len; i++) {
        crc ^= data[i];
        for (bit = 0; bit < 8; bit++)
            crc = (crc >> 1) ^ (0xedb88320u & (uint32_t)(-(int32_t)(crc & 1)));
    }
    return crc ^ 0xffffffffu;
}

int cairn_frame_encode(uint8_t *out, size_t outcap, size_t *outlen,
                       uint8_t type, const void *payload, size_t payloadlen)
{
    size_t need;

    if (out == NULL || outlen == NULL) return CAIRN_ERR_ARG;
    if (payload == NULL && payloadlen > 0) return CAIRN_ERR_ARG;
    if (payloadlen > CAIRN_FRAME_MAX) return CAIRN_ERR_ARG;

    need = cairn_frame_size(payloadlen);
    if (outcap < need) return CAIRN_ERR_BUFFER;

    out[0] = CAIRN_FRAME_MAGIC0;
    out[1] = CAIRN_FRAME_MAGIC1;
    out[2] = CAIRN_FRAME_VERSION;
    out[3] = type;
    put_u32(out + 4, (uint32_t)payloadlen);
    if (payloadlen > 0) memmove(out + 8, payload, payloadlen);
    put_u32(out + 8 + payloadlen, crc32(out, 8 + payloadlen));

    *outlen = need;
    return CAIRN_OK;
}

int cairn_frame_decode(cairn_frame *out, size_t *consumed,
                       const void *buf, size_t len)
{
    const uint8_t *p = (const uint8_t *)buf;
    uint32_t declared;
    size_t need;
    uint32_t want;

    if (out == NULL || consumed == NULL || buf == NULL) return CAIRN_ERR_ARG;
    if (len < CAIRN_FRAME_OVERHEAD) return CAIRN_ERR_FORMAT;
    if (p[0] != CAIRN_FRAME_MAGIC0 || p[1] != CAIRN_FRAME_MAGIC1)
        return CAIRN_ERR_FORMAT;
    if (p[2] != CAIRN_FRAME_VERSION) return CAIRN_ERR_FORMAT;

    declared = get_u32(p + 4);
    /* Check the bound before the addition so a huge value cannot wrap size_t. */
    if (declared > CAIRN_FRAME_MAX) return CAIRN_ERR_FORMAT;

    need = cairn_frame_size((size_t)declared);
    if (len < need) return CAIRN_ERR_FORMAT;

    want = get_u32(p + 8 + declared);
    if (want != crc32(p, 8 + declared)) return CAIRN_ERR_FORMAT;

    out->type = p[3];
    out->payload = p + 8;
    out->payloadlen = declared;
    *consumed = need;
    return CAIRN_OK;
}