#include "test.h"

#include <string.h>

#include "cairn/wire.h"

CT_TEST(wire_frame_roundtrip)
{
    uint8_t buf[256];
    size_t len = 0;
    cairn_frame f;

    CT_ASSERT_EQ_INT(cairn_frame_encode(buf, sizeof buf, &len, CAIRN_FRAME_DATA,
                                        "payload", 7), CAIRN_OK);
    CT_ASSERT_EQ_INT(len, cairn_frame_size(7));
    CT_ASSERT_EQ_INT(len, CAIRN_FRAME_OVERHEAD + 7);

    memset(&f, 0, sizeof f);
    {
        size_t used = 0;
        CT_ASSERT_EQ_INT(cairn_frame_decode(&f, &used, buf, len), CAIRN_OK);
        CT_ASSERT_EQ_INT(used, len);
    }
    CT_ASSERT_EQ_INT(f.type, CAIRN_FRAME_DATA);
    CT_ASSERT_EQ_INT(f.payloadlen, 7);
    CT_ASSERT_MEM_EQ(f.payload, "payload", 7);
}

/* An empty payload is legal: ping and bye carry nothing. */
CT_TEST(wire_empty_payload)
{
    uint8_t buf[64];
    size_t len = 0;
    cairn_frame f;
    size_t used = 0;

    CT_ASSERT_EQ_INT(cairn_frame_encode(buf, sizeof buf, &len, CAIRN_FRAME_PING,
                                        NULL, 0), CAIRN_OK);
    CT_ASSERT_EQ_INT(len, CAIRN_FRAME_OVERHEAD);
    CT_ASSERT_EQ_INT(cairn_frame_decode(&f, &used, buf, len), CAIRN_OK);
    CT_ASSERT_EQ_INT(f.type, CAIRN_FRAME_PING);
    CT_ASSERT_EQ_INT(f.payloadlen, 0);
}

/* Two frames back to back: the first decode must report where the next starts. */
CT_TEST(wire_back_to_back)
{
    uint8_t buf[256];
    size_t len = 0, total = 0;
    cairn_frame f;
    size_t used = 0;

    CT_ASSERT_EQ_INT(cairn_frame_encode(buf, sizeof buf, &len, CAIRN_FRAME_HELLO,
                                        "ab", 2), CAIRN_OK);
    total = len;
    CT_ASSERT_EQ_INT(cairn_frame_encode(buf + total, sizeof buf - total, &len,
                                        CAIRN_FRAME_BYE, "cd", 2), CAIRN_OK);
    total += len;

    CT_ASSERT_EQ_INT(cairn_frame_decode(&f, &used, buf, total), CAIRN_OK);
    CT_ASSERT_EQ_INT(f.type, CAIRN_FRAME_HELLO);
    CT_ASSERT_EQ_INT(cairn_frame_decode(&f, &used, buf + used, total - used), CAIRN_OK);
    CT_ASSERT_EQ_INT(f.type, CAIRN_FRAME_BYE);
    CT_ASSERT_MEM_EQ(f.payload, "cd", 2);
}

/* Truncation at every possible point must be refused, never read past the end. */
CT_TEST(wire_truncated_rejected)
{
    uint8_t buf[64];
    size_t len = 0;
    size_t cut;

    CT_ASSERT_EQ_INT(cairn_frame_encode(buf, sizeof buf, &len, CAIRN_FRAME_DATA,
                                        "0123456789", 10), CAIRN_OK);

    for (cut = 0; cut < len; cut++) {
        cairn_frame f;
        size_t used = 0;
        CT_ASSERT(cairn_frame_decode(&f, &used, buf, cut) != CAIRN_OK);
    }
}

CT_TEST(wire_bad_magic_rejected)
{
    uint8_t buf[64];
    size_t len = 0;
    cairn_frame f;
    size_t used = 0;

    CT_ASSERT_EQ_INT(cairn_frame_encode(buf, sizeof buf, &len, CAIRN_FRAME_DATA,
                                        "x", 1), CAIRN_OK);
    buf[0] ^= 0xff;
    CT_ASSERT_EQ_INT(cairn_frame_decode(&f, &used, buf, len), CAIRN_ERR_FORMAT);

    CT_ASSERT_EQ_INT(cairn_frame_encode(buf, sizeof buf, &len, CAIRN_FRAME_DATA,
                                        "x", 1), CAIRN_OK);
    buf[2] = CAIRN_FRAME_VERSION + 1;
    CT_ASSERT_EQ_INT(cairn_frame_decode(&f, &used, buf, len), CAIRN_ERR_FORMAT);
}

/* A corrupted payload must fail the checksum, not be handed to the caller. */
CT_TEST(wire_checksum_rejected)
{
    uint8_t buf[64];
    size_t len = 0;
    cairn_frame f;
    size_t used = 0;

    CT_ASSERT_EQ_INT(cairn_frame_encode(buf, sizeof buf, &len, CAIRN_FRAME_DATA,
                                        "abc", 3), CAIRN_OK);
    buf[CAIRN_FRAME_OVERHEAD - 4] ^= 0x01;
    CT_ASSERT_EQ_INT(cairn_frame_decode(&f, &used, buf, len), CAIRN_ERR_FORMAT);
}

/* A length field claiming more than the buffer holds must be refused before any
 * arithmetic that could overflow. */
CT_TEST(wire_oversize_length_rejected)
{
    uint8_t buf[64];
    size_t len = 0;
    cairn_frame f;
    size_t used = 0;

    CT_ASSERT_EQ_INT(cairn_frame_encode(buf, sizeof buf, &len, CAIRN_FRAME_DATA,
                                        "abc", 3), CAIRN_OK);
    /* 0xffffffff payload length. */
    buf[4] = 0xff;
    buf[5] = 0xff;
    buf[6] = 0xff;
    buf[7] = 0xff;
    CT_ASSERT_EQ_INT(cairn_frame_decode(&f, &used, buf, len), CAIRN_ERR_FORMAT);

    /* A length above CAIRN_FRAME_MAX but small enough not to overflow. */
    CT_ASSERT_EQ_INT(cairn_frame_encode(buf, sizeof buf, &len, CAIRN_FRAME_DATA,
                                        "abc", 3), CAIRN_OK);
    {
        uint32_t big = CAIRN_FRAME_MAX + 1;
        buf[4] = (uint8_t)big;
        buf[5] = (uint8_t)(big >> 8);
        buf[6] = (uint8_t)(big >> 16);
        buf[7] = (uint8_t)(big >> 24);
    }
    CT_ASSERT_EQ_INT(cairn_frame_decode(&f, &used, buf, len), CAIRN_ERR_FORMAT);
}

CT_TEST(wire_short_out_buffer_rejected)
{
    uint8_t buf[16];
    size_t len = 0;

    CT_ASSERT_EQ_INT(cairn_frame_encode(buf, sizeof buf, &len, CAIRN_FRAME_DATA,
                                        "0123456789", 10), CAIRN_ERR_BUFFER);
    CT_ASSERT_EQ_INT(cairn_frame_encode(NULL, 16, &len, CAIRN_FRAME_DATA, "x", 1),
                     CAIRN_ERR_ARG);
    CT_ASSERT_EQ_INT(cairn_frame_decode(NULL, NULL, buf, sizeof buf), CAIRN_ERR_ARG);
}

/* The encoded size helper must never report a smaller value than the encoder
 * needs, including at the maximum payload. */
CT_TEST(wire_size_helper_matches)
{
    size_t n;
    for (n = 0; n <= 300; n += 37)
        CT_ASSERT_EQ_INT(cairn_frame_size(n), CAIRN_FRAME_OVERHEAD + n);
}

void ct_reg_wire(void)
{
    CT_REG(wire_frame_roundtrip);
    CT_REG(wire_empty_payload);
    CT_REG(wire_back_to_back);
    CT_REG(wire_truncated_rejected);
    CT_REG(wire_bad_magic_rejected);
    CT_REG(wire_checksum_rejected);
    CT_REG(wire_oversize_length_rejected);
    CT_REG(wire_short_out_buffer_rejected);
    CT_REG(wire_size_helper_matches);
}