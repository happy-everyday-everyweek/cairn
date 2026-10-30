/* cairn: offline bundles.
 *
 * A bundle is a self contained encrypted file that travels through anything: a USB
 * stick, a cloud drive, an email attachment, a chat app. Whoever holds the matching
 * identity opens it later, on any platform, with no network and the sender long
 * offline.
 *
 * This is the second half of Cairn. A live session needs both devices awake at once;
 * a bundle does not. Same two devices, same keys, a different shape of delivery.
 *
 * The key is a Diffie-Hellman between a one-time X25519 key made for this bundle and
 * the recipient's static key. Only the intended device can recompute it, and once
 * the sender forgets its one-time secret, nobody can recover it from the file.
 *
 * Two levels are offered:
 *
 *   cairn_seal / cairn_unseal    one buffer in, one buffer out. What an application
 *                                normally wants.
 *   cairn_bundle_*               chunk level, for streaming a large file to disk
 *                                without holding the plaintext in memory.
 */
#ifndef CAIRN_BUNDLE_H
#define CAIRN_BUNDLE_H

#include <stddef.h>
#include <stdint.h>

#include "cairn/cairn.h"
#include "cairn/crypto.h"
#include "cairn/identity.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Plaintext bytes per chunk. 64 KiB keeps the overhead near 0.02% while staying
 * small enough that a phone decrypts one chunk without noticing. */
#define CAIRN_BUNDLE_CHUNK 65536

#define CAIRN_BUNDLE_MAGIC "CRNB"
#define CAIRN_BUNDLE_VERSION 1

/* Everything before the chunk bodies: magic, version, flags, chunk size, length,
 * chunk count, ephemeral key, sender key, nonce prefix. */
#define CAIRN_BUNDLE_HEADER_BYTES     (4 + 1 + 1 + 4 + 8 + 4 + CAIRN_X25519_BYTES + CAIRN_PUBKEY_BYTES + 16)

#define CAIRN_BUNDLE_SIG_BYTES CAIRN_ED25519_SIG_BYTES

/* Bytes a bundle of this plaintext size occupies, signature included. */
uint64_t cairn_bundle_size(uint64_t plaintext_len);

/* ------------------------------------------------------------------- simple */

/* Encrypts len bytes for the holder of recipient. out must hold
 * cairn_bundle_size(len) bytes. Pass the recipient's public key, which is what a
 * paired device hands over when it is added.
 *
 * The result is a single opaque blob: it can be uploaded, emailed, copied to a USB
 * stick, and only that one device can open it. */
int cairn_seal(uint8_t *out, size_t outcap, size_t *outlen,
               const cairn_identity *sender, const cairn_pubkey *recipient,
               const void *plain, size_t len);

/* Decrypts a bundle produced by cairn_seal. Fails with CAIRN_ERR_AUTH when the
 * bundle was sealed to a different device, or was modified in any way. */
int cairn_unseal(uint8_t *out, size_t outcap, size_t *outlen,
                 const cairn_identity *self, const void *bundle, size_t len);

/* -------------------------------------------------------------- streaming */

typedef struct {
    /* Who signs and identifies the bundle. */
    const cairn_identity *sender;
    /* Whose key opens it. */
    const cairn_pubkey *recipient;
} cairn_bundle_opts;

/* Parsed header, so a caller can size its buffers before reading the bodies. */
typedef struct {
    uint8_t flags;
    uint32_t chunk_size;
    uint32_t chunk_count;
    uint64_t plaintext_len;
    uint8_t eph_pub[CAIRN_X25519_BYTES];
    uint8_t nonce_prefix[16];
    cairn_pubkey sender;
    /* Offset of the first chunk body, for seeking inside a file. */
    size_t chunks_offset;
} cairn_bundle_info;

/* Writes the header and hands back the wrapping key and nonce prefix, so the caller
 * can seal chunks one at a time without keeping the identity around. */
int cairn_bundle_begin(uint8_t *out, size_t outcap, size_t *written,
                       const cairn_bundle_opts *opts, uint64_t plaintext_len,
                       uint8_t wrap_key[CAIRN_KEY_BYTES], uint8_t nonce_prefix[16]);

/* Seals one chunk. index must run from zero upward. */
int cairn_bundle_chunk(uint8_t *dst, size_t dstcap, size_t *written,
                       const uint8_t wrap_key[CAIRN_KEY_BYTES],
                       const uint8_t nonce_prefix[16],
                       uint32_t index, const void *plain, size_t len);

/* Signs the finished bundle. The signature covers the header and every chunk. */
int cairn_bundle_sign(uint8_t out[CAIRN_ED25519_SIG_BYTES], const cairn_identity *sender,
                      const uint8_t *bundle, size_t bundle_len);

/* Parses a header. Touches only the first CAIRN_BUNDLE_HEADER_BYTES, so reading the
 * shape of a huge file costs one small read. */
int cairn_bundle_peek(cairn_bundle_info *info, const void *bundle, size_t len);

/* Checks the signature and that this device can derive the wrapping key. Called
 * before decrypting anything so a wrong download fails early. */
int cairn_bundle_verify(const cairn_bundle_info *info, const cairn_identity *self,
                        const void *bundle, size_t len);

/* Decrypts one chunk. The index comes from the caller, not the data, so a chunk
 * moved to another position fails the tag check. */
int cairn_bundle_open_chunk(uint8_t *dst, size_t dstcap, size_t *written,
                            const cairn_bundle_info *info, const cairn_identity *self,
                            uint32_t index, const void *chunk, size_t chunk_len);

#ifdef __cplusplus
}
#endif

#endif /* CAIRN_BUNDLE_H */