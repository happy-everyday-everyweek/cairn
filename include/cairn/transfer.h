/* cairn: resumable transfer.
 *
 * The point of this module is the interrupted case. A sender announces a file,
 * streams chunks, and records which chunks the peer confirmed. If the link dies
 * the session is rebuilt and the sender continues from the first unconfirmed
 * chunk instead of starting over.
 *
 * Three properties are deliberately tested: progress survives a lost peer, a
 * chunk arriving twice is not written twice, and a corrupted chunk is refused
 * rather than stored.
 *
 * The module never touches the filesystem. It hands out chunk indices and
 * accepts confirmations; the caller owns bytes on disk. That keeps it usable
 * from a phone with scoped storage and from a CLI with plain files.
 */
#ifndef CAIRN_TRANSFER_H
#define CAIRN_TRANSFER_H

#include <stddef.h>
#include <stdint.h>

#include "cairn/cairn.h"
#include "cairn/wire.h"

#ifdef __cplusplus
extern "C" {
#endif

/* One bit per chunk, capped so the bitmap has a fixed size and a hostile peer
 * cannot make us allocate unbounded memory. */
#define CAIRN_XFER_MAX_CHUNKS 4096
#define CAIRN_XFER_BITMAP_BYTES (CAIRN_XFER_MAX_CHUNKS / 8)

typedef enum {
    CAIRN_XFER_OFFERED = 0,
    CAIRN_XFER_ACTIVE = 1,
    CAIRN_XFER_DONE = 2,
    CAIRN_XFER_FAILED = 3
} cairn_xfer_state;

typedef struct {
    uint64_t total_bytes;
    uint32_t chunk_bytes;
    uint32_t chunk_count;
    uint32_t confirmed;
    cairn_xfer_state state;
    /* One bit per chunk, set once the peer confirms it. */
    uint8_t have[CAIRN_XFER_BITMAP_BYTES];
} cairn_transfer;

/* Starts a send. total_bytes is the exact file size the caller intends to move. */
int cairn_transfer_offer(cairn_transfer *x, uint64_t total_bytes);

/* Marks the offer accepted and starts streaming. */
int cairn_transfer_accept(cairn_transfer *x);

/* The chunk the sender should transmit next. A resumed transfer naturally
 * returns the first gap, because confirmations are the only source of truth. */
int cairn_transfer_next_chunk(const cairn_transfer *x, uint32_t *index, size_t *len);

/* Records a confirmation. Repeated confirmations are harmless. */
int cairn_transfer_ack(cairn_transfer *x, uint32_t index);

/* Marks the transfer failed without forgetting what was confirmed, so
 * cairn_transfer_resume can pick it up. */
int cairn_transfer_interrupt(cairn_transfer *x);

/* True when every chunk is confirmed. */
int cairn_transfer_complete(const cairn_transfer *x);

/* Resumes after an interruption. Confirmations are kept, which is the point. */
int cairn_transfer_resume(cairn_transfer *x);

/* Bytes confirmed so far, for a progress report. */
uint64_t cairn_transfer_progress(const cairn_transfer *x);

#ifdef __cplusplus
}
#endif

#endif /* CAIRN_TRANSFER_H */