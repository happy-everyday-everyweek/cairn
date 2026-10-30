#include "test.h"

#include <string.h>

#include "cairn/transfer.h"

CT_TEST(transfer_offer_sets_shape)
{
    cairn_transfer x;

    memset(&x, 0xaa, sizeof x);
    CT_ASSERT_EQ_INT(cairn_transfer_offer(&x, 1000000), CAIRN_OK);
    CT_ASSERT_EQ_INT(x.total_bytes, 1000000);
    CT_ASSERT_EQ_INT(x.chunk_bytes, CAIRN_CHUNK_BYTES);
    CT_ASSERT_EQ_INT(x.state, CAIRN_XFER_OFFERED);
    CT_ASSERT_EQ_INT(x.confirmed, 0);
    /* ceil(1000000 / 16384) = 62 */
    CT_ASSERT_EQ_INT(x.chunk_count, 62);
    CT_ASSERT_EQ_INT(cairn_transfer_complete(&x), 0);
}

CT_TEST(transfer_exact_multiple_chunks)
{
    cairn_transfer x;

    CT_ASSERT_EQ_INT(cairn_transfer_offer(&x, CAIRN_CHUNK_BYTES * 4), CAIRN_OK);
    CT_ASSERT_EQ_INT(x.chunk_count, 4);
    CT_ASSERT_EQ_INT(cairn_transfer_offer(&x, 1), CAIRN_OK);
    CT_ASSERT_EQ_INT(x.chunk_count, 1);
    CT_ASSERT_EQ_INT(cairn_transfer_offer(&x, 0), CAIRN_ERR_ARG);
}

CT_TEST(transfer_offer_rejects_oversize)
{
    cairn_transfer x;

    /* Beyond the bitmap cap the offer must be refused, not silently truncated. */
    CT_ASSERT_EQ_INT(cairn_transfer_offer(&x, (uint64_t)CAIRN_CHUNK_BYTES *
                                              (CAIRN_XFER_MAX_CHUNKS + 1)),
                     CAIRN_ERR_ARG);
    CT_ASSERT_EQ_INT(cairn_transfer_offer(&x, (uint64_t)CAIRN_CHUNK_BYTES *
                                              CAIRN_XFER_MAX_CHUNKS),
                     CAIRN_OK);
    CT_ASSERT_EQ_INT(x.chunk_count, CAIRN_XFER_MAX_CHUNKS);
}

/* The sender must be told the first gap, and chunk lengths must be correct at
 * the tail where the file does not divide evenly. */
CT_TEST(transfer_next_chunk_sizes)
{
    cairn_transfer x;
    uint32_t index = 0;
    size_t len = 0;

    CT_ASSERT_EQ_INT(cairn_transfer_offer(&x, CAIRN_CHUNK_BYTES * 2 + 100), CAIRN_OK);
    CT_ASSERT_EQ_INT(cairn_transfer_accept(&x), CAIRN_OK);

    CT_ASSERT_EQ_INT(cairn_transfer_next_chunk(&x, &index, &len), CAIRN_OK);
    CT_ASSERT_EQ_INT(index, 0);
    CT_ASSERT_EQ_INT(len, CAIRN_CHUNK_BYTES);

    CT_ASSERT_EQ_INT(cairn_transfer_ack(&x, 0), CAIRN_OK);
    CT_ASSERT_EQ_INT(cairn_transfer_ack(&x, 1), CAIRN_OK);
    CT_ASSERT_EQ_INT(cairn_transfer_next_chunk(&x, &index, &len), CAIRN_OK);
    CT_ASSERT_EQ_INT(index, 2);
    CT_ASSERT_EQ_INT(len, 100);
}

/* The interruption case, which is the reason this module exists. */
CT_TEST(transfer_resumes_from_gap)
{
    cairn_transfer x;
    uint32_t index = 0;
    size_t len = 0;
    uint64_t before;

    CT_ASSERT_EQ_INT(cairn_transfer_offer(&x, CAIRN_CHUNK_BYTES * 10), CAIRN_OK);
    CT_ASSERT_EQ_INT(cairn_transfer_accept(&x), CAIRN_OK);

    /* Confirm 0..3, then the link dies. */
    for (uint32_t i = 0; i < 4; i++)
        CT_ASSERT_EQ_INT(cairn_transfer_ack(&x, i), CAIRN_OK);
    before = cairn_transfer_progress(&x);
    CT_ASSERT_EQ_INT(before, (uint64_t)CAIRN_CHUNK_BYTES * 4);

    CT_ASSERT_EQ_INT(cairn_transfer_interrupt(&x), CAIRN_OK);
    CT_ASSERT_EQ_INT(x.state, CAIRN_XFER_FAILED);
    /* A failed transfer refuses new work until it is resumed. */
    CT_ASSERT_EQ_INT(cairn_transfer_next_chunk(&x, &index, &len), CAIRN_ERR_STATE);

    CT_ASSERT_EQ_INT(cairn_transfer_resume(&x), CAIRN_OK);
    CT_ASSERT_EQ_INT(x.state, CAIRN_XFER_ACTIVE);
    /* Progress is preserved, and the sender continues at the first gap. */
    CT_ASSERT_EQ_INT(cairn_transfer_progress(&x), before);
    CT_ASSERT_EQ_INT(cairn_transfer_next_chunk(&x, &index, &len), CAIRN_OK);
    CT_ASSERT_EQ_INT(index, 4);
}

/* A gap in the middle must be found before later confirmed chunks. */
CT_TEST(transfer_finds_middle_gap)
{
    cairn_transfer x;
    uint32_t index = 0;
    size_t len = 0;

    CT_ASSERT_EQ_INT(cairn_transfer_offer(&x, CAIRN_CHUNK_BYTES * 8), CAIRN_OK);
    CT_ASSERT_EQ_INT(cairn_transfer_accept(&x), CAIRN_OK);
    CT_ASSERT_EQ_INT(cairn_transfer_ack(&x, 0), CAIRN_OK);
    CT_ASSERT_EQ_INT(cairn_transfer_ack(&x, 2), CAIRN_OK);
    CT_ASSERT_EQ_INT(cairn_transfer_ack(&x, 3), CAIRN_OK);
    CT_ASSERT_EQ_INT(cairn_transfer_next_chunk(&x, &index, &len), CAIRN_OK);
    CT_ASSERT_EQ_INT(index, 1);
}

/* A duplicate confirmation must not advance the counter twice. */
CT_TEST(transfer_duplicate_ack_idempotent)
{
    cairn_transfer x;
    uint64_t once;

    CT_ASSERT_EQ_INT(cairn_transfer_offer(&x, CAIRN_CHUNK_BYTES * 4), CAIRN_OK);
    CT_ASSERT_EQ_INT(cairn_transfer_accept(&x), CAIRN_OK);
    CT_ASSERT_EQ_INT(cairn_transfer_ack(&x, 1), CAIRN_OK);
    once = cairn_transfer_progress(&x);
    CT_ASSERT_EQ_INT(cairn_transfer_ack(&x, 1), CAIRN_OK);
    CT_ASSERT_EQ_INT(cairn_transfer_progress(&x), once);
    CT_ASSERT_EQ_INT(x.confirmed, 1);
}

CT_TEST(transfer_out_of_range_ack_rejected)
{
    cairn_transfer x;

    CT_ASSERT_EQ_INT(cairn_transfer_offer(&x, CAIRN_CHUNK_BYTES * 2), CAIRN_OK);
    CT_ASSERT_EQ_INT(cairn_transfer_accept(&x), CAIRN_OK);
    CT_ASSERT_EQ_INT(cairn_transfer_ack(&x, 2), CAIRN_ERR_ARG);
    CT_ASSERT_EQ_INT(cairn_transfer_ack(&x, 0xffffffffu), CAIRN_ERR_ARG);
    CT_ASSERT_EQ_INT(x.confirmed, 0);
}

CT_TEST(transfer_completes_when_all_confirmed)
{
    cairn_transfer x;
    uint32_t index = 0;
    size_t len = 0;

    CT_ASSERT_EQ_INT(cairn_transfer_offer(&x, CAIRN_CHUNK_BYTES * 3), CAIRN_OK);
    CT_ASSERT_EQ_INT(cairn_transfer_accept(&x), CAIRN_OK);
    for (uint32_t i = 0; i < 3; i++)
        CT_ASSERT_EQ_INT(cairn_transfer_ack(&x, i), CAIRN_OK);

    CT_ASSERT_EQ_INT(cairn_transfer_complete(&x), 1);
    CT_ASSERT_EQ_INT(cairn_transfer_next_chunk(&x, &index, &len), CAIRN_ERR_STATE);
    CT_ASSERT_EQ_INT(cairn_transfer_progress(&x), (uint64_t)CAIRN_CHUNK_BYTES * 3);
}

/* Confirmations before the offer is accepted must be refused: a peer cannot
 * skip the handshake and pretend chunks landed. */
CT_TEST(transfer_state_machine)
{
    cairn_transfer x;

    memset(&x, 0, sizeof x);
    CT_ASSERT_EQ_INT(cairn_transfer_accept(&x), CAIRN_ERR_STATE);
    CT_ASSERT_EQ_INT(cairn_transfer_ack(&x, 0), CAIRN_ERR_STATE);

    CT_ASSERT_EQ_INT(cairn_transfer_offer(&x, 100), CAIRN_OK);
    CT_ASSERT_EQ_INT(cairn_transfer_ack(&x, 0), CAIRN_ERR_STATE);
    CT_ASSERT_EQ_INT(cairn_transfer_accept(&x), CAIRN_OK);
    CT_ASSERT_EQ_INT(cairn_transfer_ack(&x, 0), CAIRN_OK);
    CT_ASSERT_EQ_INT(x.state, CAIRN_XFER_DONE);
    /* Accepting twice is harmless. */
    CT_ASSERT_EQ_INT(cairn_transfer_accept(&x), CAIRN_OK);
    CT_ASSERT_EQ_INT(cairn_transfer_offer(NULL, 1), CAIRN_ERR_ARG);
}

void ct_reg_transfer(void)
{
    CT_REG(transfer_offer_sets_shape);
    CT_REG(transfer_exact_multiple_chunks);
    CT_REG(transfer_offer_rejects_oversize);
    CT_REG(transfer_next_chunk_sizes);
    CT_REG(transfer_resumes_from_gap);
    CT_REG(transfer_finds_middle_gap);
    CT_REG(transfer_duplicate_ack_idempotent);
    CT_REG(transfer_out_of_range_ack_rejected);
    CT_REG(transfer_completes_when_all_confirmed);
    CT_REG(transfer_state_machine);
}