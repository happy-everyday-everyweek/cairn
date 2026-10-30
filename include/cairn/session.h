/* cairn: authenticated session with a real DH ratchet.
 *
 * Handshake (X3DH shaped, extended with a KEM):
 *
 *   initiator -> responder : init_static_dh_pub || init_eph_pub || kem_ct
 *   responder -> initiator : resp_eph_pub
 *
 * Three Diffie-Hellman shares are combined:
 *   DH1 = DH(init_eph,    resp_static)   binds the responder identity
 *   DH2 = DH(init_eph,    resp_eph)      forward secrecy for the responder
 *   DH3 = DH(init_static, resp_eph)      binds the initiator identity
 *
 * The three outputs are sorted before concatenation, so both sides agree on byte
 * order without a role check. The ML-KEM-768 shared secret is appended, which
 * keeps the session secret if X25519 is broken by a future quantum machine. The
 * two static DH public keys are appended too, sorted, so the derived key binds
 * the identities even though the responder never sees the full identity blob.
 *
 * After the handshake a real DH ratchet runs: every CAIRN_RATCHET_INTERVAL
 * messages the sender advertises a fresh ratchet public key and folds a new DH
 * output into the root key. Receivers mirror the step on seeing a new key. This
 * is what the reference implementation lacked: its ratchet public key never
 * changed, so a leaked chain key stayed useful forever.
 */
#ifndef CAIRN_SESSION_H
#define CAIRN_SESSION_H

#include <stddef.h>
#include <stdint.h>

#include "cairn/cairn.h"
#include "cairn/crypto.h"
#include "cairn/identity.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Messages per chain before a ratchet step is forced. */
#define CAIRN_RATCHET_INTERVAL 8

/* How many out of order message keys to retain for late arrivals. */
#define CAIRN_MAX_SKIPPED 32

#define CAIRN_HANDSHAKE_INIT_BYTES \
    (CAIRN_X25519_BYTES + CAIRN_X25519_BYTES + CAIRN_MLKEM_CT_BYTES)
#define CAIRN_HANDSHAKE_RESP_BYTES (CAIRN_X25519_BYTES)

typedef enum {
    CAIRN_ROLE_INITIATOR = 0,
    CAIRN_ROLE_RESPONDER = 1
} cairn_role;

typedef struct {
    uint32_t epoch;      /* ratchet generation, increments per DH step */
    uint32_t index;      /* message number within the current chain */
    uint8_t dh_pub[CAIRN_X25519_BYTES]; /* sender's current ratchet key */
} cairn_header;

typedef struct {
    uint8_t root_key[CAIRN_KEY_BYTES];
    uint8_t send_chain[CAIRN_KEY_BYTES];
    uint8_t recv_chain[CAIRN_KEY_BYTES];

    uint8_t send_dh_pub[CAIRN_X25519_BYTES];
    uint8_t send_dh_sec[CAIRN_X25519_BYTES];
    uint8_t recv_dh_pub[CAIRN_X25519_BYTES];

    uint8_t own_static_pub[CAIRN_X25519_BYTES];
    uint8_t peer_static_pub[CAIRN_X25519_BYTES];

    uint32_t send_epoch;
    uint32_t recv_epoch;
    uint32_t send_index;
    uint32_t recv_index;
    uint32_t sent_in_chain;

    cairn_role role;
    int established;
    int pending;

    /* State parked between init and finish. */
    uint8_t pending_dh[3][CAIRN_X25519_BYTES];
    uint8_t pending_ss[CAIRN_MLKEM_SS_BYTES];
    uint8_t pending_own_static[CAIRN_X25519_BYTES];
    uint8_t pending_peer_static[CAIRN_X25519_BYTES];

    /* Keys for messages that arrived out of order, consumed on use. */
    struct {
        uint32_t epoch;
        uint32_t index;
        int used;
        uint8_t key[CAIRN_KEY_BYTES];
    } skipped[CAIRN_MAX_SKIPPED];
} cairn_session;

/* Initiator step one. Produces the blob to send and parks the pending state. */
int cairn_session_init(cairn_session *s,
                       const cairn_identity *self,
                       const cairn_pubkey *peer,
                       uint8_t out[CAIRN_HANDSHAKE_INIT_BYTES]);

/* Responder side: consumes the initiator blob and produces its reply. */
int cairn_session_respond(cairn_session *s,
                          const cairn_identity *self,
                          uint8_t out[CAIRN_HANDSHAKE_RESP_BYTES],
                          const uint8_t *init, size_t initlen);

/* Initiator side: consumes the responder blob and completes the setup. */
int cairn_session_finish(cairn_session *s,
                         const uint8_t *resp, size_t resplen);

/* Confirms the peer holds the same key material by checking a keyed tag. The
 * initiator sends the tag first; the responder verifies and replies. */
int cairn_session_confirm_tag(uint8_t out[CAIRN_TAG_BYTES], const cairn_session *s,
                              const char *label);
int cairn_session_check_tag(const cairn_session *s, const char *label,
                            const uint8_t tag[CAIRN_TAG_BYTES]);

/* Encrypts one message. out must hold plaintextlen + CAIRN_TAG_BYTES and the
 * header is written to hdr separately so the caller controls framing. */
int cairn_session_seal(const cairn_session *s, cairn_header *hdr,
                       uint8_t *out, size_t outcap, size_t *outlen,
                       const void *plaintext, size_t plaintextlen);

/* Decrypts one message. Returns CAIRN_ERR_REPLAY for a message already seen
 * and CAIRN_ERR_AUTH when the tag does not verify. */
int cairn_session_open(cairn_session *s, const cairn_header *hdr,
                       uint8_t *out, size_t outcap, size_t *outlen,
                       const void *ciphertext, size_t ciphertextlen);

void cairn_session_clear(cairn_session *s);

#ifdef __cplusplus
}
#endif

#endif /* CAIRN_SESSION_H */