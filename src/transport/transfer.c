/* cairn: resumable transfer bookkeeping.
 *
 * The bitmap of confirmed chunks is the only durable state. Everything else can
 * be recomputed from the file size, which is why a resume after a dropped link
 * is just "clear the failed flag and ask for the first unset bit".
 */
#include "cairn/transfer.h"

#include <string.h>

static int bit_get(const uint8_t *bits, uint32_t index)
{
    return (bits[index / 8] >> (index % 8)) & 1;
}

static void bit_set(uint8_t *bits, uint32_t index)
{
    bits[index / 8] |= (uint8_t)(1u << (index % 8));
}

int cairn_transfer_offer(cairn_transfer *x, uint64_t total_bytes)
{
    uint64_t chunks;

    if (x == NULL || total_bytes == 0) return CAIRN_ERR_ARG;

    chunks = (total_bytes + CAIRN_CHUNK_BYTES - 1) / CAIRN_CHUNK_BYTES;
    if (chunks > CAIRN_XFER_MAX_CHUNKS) return CAIRN_ERR_ARG;

    memset(x, 0, sizeof *x);
    x->total_bytes = total_bytes;
    x->chunk_bytes = CAIRN_CHUNK_BYTES;
    x->chunk_count = (uint32_t)chunks;
    x->state = CAIRN_XFER_OFFERED;
    return CAIRN_OK;
}

int cairn_transfer_accept(cairn_transfer *x)
{
    if (x == NULL) return CAIRN_ERR_ARG;
    /* An uninitialised struct has zero chunks; refuse rather than call it done. */
    if (x->chunk_count == 0) return CAIRN_ERR_STATE;
    if (x->state == CAIRN_XFER_OFFERED) {
        x->state = CAIRN_XFER_ACTIVE;
        return CAIRN_OK;
    }
    /* Already active or done: accepting again is harmless. */
    if (x->state == CAIRN_XFER_ACTIVE || x->state == CAIRN_XFER_DONE) return CAIRN_OK;
    return CAIRN_ERR_STATE;
}

int cairn_transfer_next_chunk(const cairn_transfer *x, uint32_t *index, size_t *len)
{
    uint32_t i;

    if (x == NULL || index == NULL || len == NULL) return CAIRN_ERR_ARG;
    if (x->state != CAIRN_XFER_ACTIVE) return CAIRN_ERR_STATE;

    for (i = 0; i < x->chunk_count; i++) {
        if (!bit_get(x->have, i)) {
            uint64_t offset = (uint64_t)i * x->chunk_bytes;
            uint64_t remain = x->total_bytes - offset;
            *index = i;
            *len = remain < x->chunk_bytes ? (size_t)remain : (size_t)x->chunk_bytes;
            return CAIRN_OK;
        }
    }
    return CAIRN_ERR_STATE;
}

int cairn_transfer_ack(cairn_transfer *x, uint32_t index)
{
    if (x == NULL) return CAIRN_ERR_ARG;
    if (x->state != CAIRN_XFER_ACTIVE || x->chunk_count == 0) return CAIRN_ERR_STATE;
    if (index >= x->chunk_count) return CAIRN_ERR_ARG;
    if (bit_get(x->have, index)) return CAIRN_OK;

    bit_set(x->have, index);
    x->confirmed++;
    if (x->confirmed == x->chunk_count) x->state = CAIRN_XFER_DONE;
    return CAIRN_OK;
}

int cairn_transfer_interrupt(cairn_transfer *x)
{
    if (x == NULL) return CAIRN_ERR_ARG;
    if (x->state == CAIRN_XFER_DONE) return CAIRN_ERR_STATE;
    x->state = CAIRN_XFER_FAILED;
    return CAIRN_OK;
}

int cairn_transfer_complete(const cairn_transfer *x)
{
    if (x == NULL) return 0;
    return x->state == CAIRN_XFER_DONE;
}

int cairn_transfer_resume(cairn_transfer *x)
{
    if (x == NULL) return CAIRN_ERR_ARG;
    if (x->state != CAIRN_XFER_FAILED) return CAIRN_ERR_STATE;
    /* The confirmations are untouched; that is the whole trick. */
    x->state = CAIRN_XFER_ACTIVE;
    return CAIRN_OK;
}

uint64_t cairn_transfer_progress(const cairn_transfer *x)
{
    uint64_t done;

    if (x == NULL) return 0;
    /* The last chunk may be short, so count it exactly rather than letting the
     * multiplication overstate progress. */
    if (x->confirmed == x->chunk_count) return x->total_bytes;
    done = (uint64_t)x->confirmed * x->chunk_bytes;
    return done < x->total_bytes ? done : x->total_bytes;
}