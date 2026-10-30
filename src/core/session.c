/* cairn: X3DH style handshake plus a real DH ratchet.
 *
 * Two defects of the reference implementation are fixed here on purpose.
 *
 * First, its ratchet public key was taken from the static identity key and never
 * rotated, so a leaked chain key compromised the rest of the conversation. Here
 * a fresh ratchet key pair is generated every CAIRN_RATCHET_INTERVAL messages
 * and its DH output is folded into the root key.
 *
 * Second, its message keys were derived from one chain key indexed by a counter,
 * so the chain key itself never changed. Here the chain key advances after every
 * single message.
 */
#include "cairn/session.h"

#include <string.h>

#define HEADER_BYTES (4 + 4 + CAIRN_X25519_BYTES)

static const char kHandshakeDomain[] = "cairn-x3dh-v1";
static const char kChainA[] = "cairn-chain-a";
static const char kChainB[] = "cairn-chain-b";
static const char kMessageKey[] = "cairn-msg-key";
static const char kNextChain[] = "cairn-next-chain";
static const char kConfirm[] = "cairn-confirm";

/* ------------------------------------------------------------- primitives */

static void put_u32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

static void header_aad(uint8_t out[HEADER_BYTES], const cairn_header *hdr)
{
    put_u32(out, hdr->epoch);
    put_u32(out + 4, hdr->index);
    memcpy(out + 8, hdr->dh_pub, CAIRN_X25519_BYTES);
}

/* Each message key is used once, so a constant nonce would be safe. The epoch
 * and index are folded in anyway as a second line of defence. */
static void message_nonce(uint8_t nonce[CAIRN_NONCE_BYTES],
                          uint32_t epoch, uint32_t index)
{
    memset(nonce, 0, CAIRN_NONCE_BYTES);
    put_u32(nonce, epoch);
    put_u32(nonce + 4, index);
}

/* KDF_RK: folds one DH output into the root and yields a new chain key. */
static void kdf_root(uint8_t new_root[CAIRN_KEY_BYTES],
                     uint8_t chain[CAIRN_KEY_BYTES],
                     const uint8_t root[CAIRN_KEY_BYTES],
                     const uint8_t dh[CAIRN_X25519_BYTES])
{
    uint8_t digest[64];

    cairn_mac(digest, sizeof digest, root, CAIRN_KEY_BYTES, dh, CAIRN_X25519_BYTES);
    memcpy(new_root, digest, CAIRN_KEY_BYTES);
    memcpy(chain, digest + CAIRN_KEY_BYTES, CAIRN_KEY_BYTES);
    cairn_memzero(digest, sizeof digest);
}

static void advance_chain(uint8_t next[CAIRN_KEY_BYTES],
                          uint8_t message_key[CAIRN_KEY_BYTES],
                          const uint8_t chain[CAIRN_KEY_BYTES])
{
    cairn_mac(message_key, CAIRN_KEY_BYTES, chain, CAIRN_KEY_BYTES,
              kMessageKey, sizeof kMessageKey - 1);
    cairn_mac(next, CAIRN_KEY_BYTES, chain, CAIRN_KEY_BYTES,
              kNextChain, sizeof kNextChain - 1);
}

/* Installs the two directional chains. The initiator always owns chain A, so a
 * session can be resumed from a stored root key without a role check. */
static void install_chains(cairn_session *s)
{
    uint8_t a[CAIRN_KEY_BYTES], b[CAIRN_KEY_BYTES];

    cairn_mac(a, sizeof a, s->root_key, CAIRN_KEY_BYTES, kChainA, sizeof kChainA - 1);
    cairn_mac(b, sizeof b, s->root_key, CAIRN_KEY_BYTES, kChainB, sizeof kChainB - 1);

    if (s->role == CAIRN_ROLE_INITIATOR) {
        memcpy(s->send_chain, a, sizeof a);
        memcpy(s->recv_chain, b, sizeof b);
    } else {
        memcpy(s->send_chain, b, sizeof b);
        memcpy(s->recv_chain, a, sizeof a);
    }
    cairn_memzero(a, sizeof a);
    cairn_memzero(b, sizeof b);
}

/* ---------------------------------------------------------- handshake root */

static int handshake_root(cairn_session *s)
{
    uint8_t material[3 * CAIRN_X25519_BYTES + CAIRN_MLKEM_SS_BYTES + 2 * CAIRN_X25519_BYTES];
    uint8_t digest[64];
    cairn_blake2b_state st;
    uint8_t dh[3][CAIRN_X25519_BYTES];
    size_t o = 0;
    int rc;

    memcpy(dh, s->pending_dh, sizeof dh);

    /* Sort the three DH outputs. Both sides produce the same multiset, so the
     * sorted order matches without either side knowing its role. */
    for (int i = 0; i < 3; i++)
        for (int j = i + 1; j < 3; j++)
            if (memcmp(dh[j], dh[i], CAIRN_X25519_BYTES) < 0) {
                uint8_t t[CAIRN_X25519_BYTES];
                memcpy(t, dh[i], sizeof t);
                memcpy(dh[i], dh[j], sizeof t);
                memcpy(dh[j], t, sizeof t);
            }

    memcpy(material, dh[0], CAIRN_X25519_BYTES); o += CAIRN_X25519_BYTES;
    memcpy(material + o, dh[1], CAIRN_X25519_BYTES); o += CAIRN_X25519_BYTES;
    memcpy(material + o, dh[2], CAIRN_X25519_BYTES); o += CAIRN_X25519_BYTES;
    memcpy(material + o, s->pending_ss, CAIRN_MLKEM_SS_BYTES); o += CAIRN_MLKEM_SS_BYTES;

    /* Static keys are sorted too, so the binding does not depend on who is who. */
    if (memcmp(s->pending_own_static, s->pending_peer_static, CAIRN_X25519_BYTES) <= 0) {
        memcpy(material + o, s->pending_own_static, CAIRN_X25519_BYTES); o += CAIRN_X25519_BYTES;
        memcpy(material + o, s->pending_peer_static, CAIRN_X25519_BYTES); o += CAIRN_X25519_BYTES;
    } else {
        memcpy(material + o, s->pending_peer_static, CAIRN_X25519_BYTES); o += CAIRN_X25519_BYTES;
        memcpy(material + o, s->pending_own_static, CAIRN_X25519_BYTES); o += CAIRN_X25519_BYTES;
    }

    rc = cairn_blake2b_init(&st, sizeof digest, NULL, 0);
    if (rc != CAIRN_OK) return rc;
    cairn_blake2b_update(&st, kHandshakeDomain, sizeof kHandshakeDomain - 1);
    cairn_blake2b_update(&st, material, o);
    rc = cairn_blake2b_final(&st, digest, sizeof digest);
    if (rc != CAIRN_OK) return rc;

    memcpy(s->root_key, digest, CAIRN_KEY_BYTES);
    install_chains(s);

    cairn_memzero(dh, sizeof dh);
    cairn_memzero(material, sizeof material);
    cairn_memzero(digest, sizeof digest);
    return CAIRN_OK;
}

/* --------------------------------------------------------------- handshake */

int cairn_session_init(cairn_session *s,
                       const cairn_identity *self,
                       const cairn_pubkey *peer,
                       uint8_t out[CAIRN_HANDSHAKE_INIT_BYTES])
{
    uint8_t eph_pub[CAIRN_X25519_BYTES], eph_sec[CAIRN_X25519_BYTES];
    uint8_t ss[CAIRN_MLKEM_SS_BYTES];
    int rc;

    if (s == NULL || self == NULL || peer == NULL || out == NULL) return CAIRN_ERR_ARG;

    memset(s, 0, sizeof *s);
    s->role = CAIRN_ROLE_INITIATOR;

    rc = cairn_x25519_keypair(eph_pub, eph_sec);
    if (rc != CAIRN_OK) goto fail;

    /* DH1 = DH(init_eph, resp_static) */
    rc = cairn_x25519(s->pending_dh[0], eph_sec, peer->dh_pub);
    if (rc != CAIRN_OK) goto fail;
    /* DH2 = DH(init_static, resp_static), computed later from stored keys: the
     * initiator does not keep peer ephemeral yet. To keep both sides symmetric
     * the initiator uses DH(init_static, resp_static) which the responder can
     * also compute without the initiator's ephemeral. */
    rc = cairn_x25519(s->pending_dh[1], self->dh_sec, peer->dh_pub);
    if (rc != CAIRN_OK) goto fail;
    /* DH3 is DH(init_eph, resp_eph); parked until finish. */
    memset(s->pending_dh[2], 0, CAIRN_X25519_BYTES);

    rc = cairn_mlkem768_encaps(out + 2 * CAIRN_X25519_BYTES, ss, peer->kem_pub);
    if (rc != CAIRN_OK) goto fail;
    memcpy(s->pending_ss, ss, sizeof ss);

    memcpy(out, self->dh_pub, CAIRN_X25519_BYTES);
    memcpy(out + CAIRN_X25519_BYTES, eph_pub, CAIRN_X25519_BYTES);

    memcpy(s->pending_own_static, self->dh_pub, CAIRN_X25519_BYTES);
    memcpy(s->pending_peer_static, peer->dh_pub, CAIRN_X25519_BYTES);
    memcpy(s->own_static_pub, self->dh_pub, CAIRN_X25519_BYTES);
    memcpy(s->peer_static_pub, peer->dh_pub, CAIRN_X25519_BYTES);
    memcpy(s->send_dh_pub, eph_pub, CAIRN_X25519_BYTES);
    memcpy(s->send_dh_sec, eph_sec, CAIRN_X25519_BYTES);
    s->pending = 1;

    cairn_memzero(eph_sec, sizeof eph_sec);
    cairn_memzero(ss, sizeof ss);
    return CAIRN_OK;

fail:
    cairn_memzero(eph_sec, sizeof eph_sec);
    cairn_memzero(ss, sizeof ss);
    memset(s, 0, sizeof *s);
    return CAIRN_ERR_CRYPTO;
}

int cairn_session_respond(cairn_session *s,
                          const cairn_identity *self,
                          uint8_t out[CAIRN_HANDSHAKE_RESP_BYTES],
                          const uint8_t *init, size_t initlen)
{
    uint8_t peer_static[CAIRN_X25519_BYTES], peer_eph[CAIRN_X25519_BYTES];
    uint8_t eph_pub[CAIRN_X25519_BYTES], eph_sec[CAIRN_X25519_BYTES];
    uint8_t ss[CAIRN_MLKEM_SS_BYTES];
    int rc;

    if (s == NULL || self == NULL || out == NULL || init == NULL) return CAIRN_ERR_ARG;
    if (initlen != CAIRN_HANDSHAKE_INIT_BYTES) return CAIRN_ERR_FORMAT;

    memset(s, 0, sizeof *s);
    s->role = CAIRN_ROLE_RESPONDER;

    memcpy(peer_static, init, CAIRN_X25519_BYTES);
    memcpy(peer_eph, init + CAIRN_X25519_BYTES, CAIRN_X25519_BYTES);

    rc = cairn_x25519_keypair(eph_pub, eph_sec);
    if (rc != CAIRN_OK) goto fail;

    /* Mirrors of the initiator's shares, plus the responder ephemeral share. */
    rc = cairn_x25519(s->pending_dh[0], self->dh_sec, peer_eph);
    if (rc != CAIRN_OK) goto fail;
    rc = cairn_x25519(s->pending_dh[1], self->dh_sec, peer_static);
    if (rc != CAIRN_OK) goto fail;
    /* dh[2] must pair both ephemerals, matching the initiator's
     * DH(init_eph, resp_eph) computed in cairn_session_finish. */
    rc = cairn_x25519(s->pending_dh[2], eph_sec, peer_eph);
    if (rc != CAIRN_OK) goto fail;

    rc = cairn_mlkem768_decaps(ss, init + 2 * CAIRN_X25519_BYTES, self->kem_sec);
    if (rc != CAIRN_OK) goto fail;
    memcpy(s->pending_ss, ss, sizeof ss);

    memcpy(s->pending_own_static, self->dh_pub, CAIRN_X25519_BYTES);
    memcpy(s->pending_peer_static, peer_static, CAIRN_X25519_BYTES);
    memcpy(s->own_static_pub, self->dh_pub, CAIRN_X25519_BYTES);
    memcpy(s->peer_static_pub, peer_static, CAIRN_X25519_BYTES);
    memcpy(s->send_dh_pub, eph_pub, CAIRN_X25519_BYTES);
    memcpy(s->send_dh_sec, eph_sec, CAIRN_X25519_BYTES);
    memcpy(s->recv_dh_pub, peer_eph, CAIRN_X25519_BYTES);

    rc = handshake_root(s);
    if (rc != CAIRN_OK) goto fail;

    memcpy(out, eph_pub, CAIRN_X25519_BYTES);
    s->established = 1;

    cairn_memzero(eph_sec, sizeof eph_sec);
    cairn_memzero(ss, sizeof ss);
    return CAIRN_OK;

fail:
    cairn_memzero(eph_sec, sizeof eph_sec);
    cairn_memzero(ss, sizeof ss);
    memset(s, 0, sizeof *s);
    return CAIRN_ERR_CRYPTO;
}

int cairn_session_finish(cairn_session *s,
                         const uint8_t *resp, size_t resplen)
{
    uint8_t peer_eph[CAIRN_X25519_BYTES];
    int rc;

    if (s == NULL || resp == NULL) return CAIRN_ERR_ARG;
    if (resplen != CAIRN_HANDSHAKE_RESP_BYTES) return CAIRN_ERR_FORMAT;
    if (!s->pending || s->role != CAIRN_ROLE_INITIATOR) return CAIRN_ERR_STATE;

    memcpy(peer_eph, resp, CAIRN_X25519_BYTES);

    /* The third share completes the set: DH(init_static, resp_eph). */
    rc = cairn_x25519(s->pending_dh[2], s->send_dh_sec, peer_eph);
    if (rc != CAIRN_OK) return CAIRN_ERR_CRYPTO;

    memcpy(s->recv_dh_pub, peer_eph, CAIRN_X25519_BYTES);

    rc = handshake_root(s);
    if (rc != CAIRN_OK) return rc;

    s->pending = 0;
    s->established = 1;
    return CAIRN_OK;
}

/* ------------------------------------------------------------- confirmation */

static void confirm_tag(uint8_t out[CAIRN_TAG_BYTES], const cairn_session *s,
                        const char *label)
{
    cairn_blake2b_state st;

    /* Keyed by the root, so only a peer that derived the same root can produce
     * a matching tag. The label keeps different phases apart. */
    cairn_blake2b_init(&st, CAIRN_TAG_BYTES, s->root_key, CAIRN_KEY_BYTES);
    cairn_blake2b_update(&st, kConfirm, sizeof kConfirm - 1);
    cairn_blake2b_update(&st, label, strlen(label));
    cairn_blake2b_final(&st, out, CAIRN_TAG_BYTES);
}

int cairn_session_confirm_tag(uint8_t out[CAIRN_TAG_BYTES], const cairn_session *s,
                              const char *label)
{
    if (out == NULL || s == NULL || label == NULL) return CAIRN_ERR_ARG;
    if (!s->established) return CAIRN_ERR_STATE;
    confirm_tag(out, s, label);
    return CAIRN_OK;
}

int cairn_session_check_tag(const cairn_session *s, const char *label,
                            const uint8_t tag[CAIRN_TAG_BYTES])
{
    uint8_t expected[CAIRN_TAG_BYTES];

    if (s == NULL || label == NULL || tag == NULL) return CAIRN_ERR_ARG;
    if (!s->established) return CAIRN_ERR_STATE;
    confirm_tag(expected, s, label);
    if (!cairn_memeq(expected, tag, CAIRN_TAG_BYTES)) return CAIRN_ERR_AUTH;
    return CAIRN_OK;
}

/* ---------------------------------------------------------------- ratchet */

/* Generates a new sending ratchet key and folds its DH output with the peer's
 * current ratchet key into the root. Runs on the sender side only. */
static int ratchet_send_step(cairn_session *s)
{
    uint8_t new_pub[CAIRN_X25519_BYTES], new_sec[CAIRN_X25519_BYTES];
    uint8_t dh[CAIRN_X25519_BYTES];
    cairn_header probe;
    int rc;

    rc = cairn_x25519_keypair(new_pub, new_sec);
    if (rc != CAIRN_OK) return rc;

    rc = cairn_x25519(dh, new_sec, s->recv_dh_pub);
    if (rc != CAIRN_OK) {
        cairn_memzero(new_sec, sizeof new_sec);
        return rc;
    }

    /* The send chain is derived per role; kdf_root writes the raw chain, so the
     * direction split happens afterwards through install_chains-like logic. */
    {
        uint8_t next_root[CAIRN_KEY_BYTES];
        uint8_t raw_chain[CAIRN_KEY_BYTES];

        kdf_root(next_root, raw_chain, s->root_key, dh);
        memcpy(s->root_key, next_root, sizeof next_root);

        /* Mix the raw chain into this side's send chain only. */
        {
            uint8_t mixed[64];
            cairn_mac(mixed, sizeof mixed, raw_chain, CAIRN_KEY_BYTES,
                      s->send_chain, CAIRN_KEY_BYTES);
            memcpy(s->send_chain, mixed, CAIRN_KEY_BYTES);
            cairn_memzero(mixed, sizeof mixed);
        }
        cairn_memzero(next_root, sizeof next_root);
        cairn_memzero(raw_chain, sizeof raw_chain);
    }

    memcpy(s->send_dh_pub, new_pub, CAIRN_X25519_BYTES);
    memcpy(s->send_dh_sec, new_sec, CAIRN_X25519_BYTES);
    s->send_epoch++;
    s->send_index = 0;
    s->sent_in_chain = 0;

    cairn_memzero(new_sec, sizeof new_sec);
    cairn_memzero(dh, sizeof dh);
    (void)probe;
    return CAIRN_OK;
}

/* Mirrors ratchet_send_step on the receiving side when the peer advertises a
 * new ratchet key. */
static int ratchet_recv_step(cairn_session *s, const uint8_t peer_pub[CAIRN_X25519_BYTES])
{
    uint8_t dh[CAIRN_X25519_BYTES];
    uint8_t next_root[CAIRN_KEY_BYTES];
    uint8_t raw_chain[CAIRN_KEY_BYTES];
    int rc;

    rc = cairn_x25519(dh, s->send_dh_sec, peer_pub);
    if (rc != CAIRN_OK) return rc;

    kdf_root(next_root, raw_chain, s->root_key, dh);
    memcpy(s->root_key, next_root, sizeof next_root);

    {
        uint8_t mixed[64];
        cairn_mac(mixed, sizeof mixed, raw_chain, CAIRN_KEY_BYTES,
                  s->recv_chain, CAIRN_KEY_BYTES);
        memcpy(s->recv_chain, mixed, CAIRN_KEY_BYTES);
        cairn_memzero(mixed, sizeof mixed);
    }

    memcpy(s->recv_dh_pub, peer_pub, CAIRN_X25519_BYTES);
    s->recv_epoch++;
    s->recv_index = 0;

    cairn_memzero(next_root, sizeof next_root);
    cairn_memzero(raw_chain, sizeof raw_chain);
    cairn_memzero(dh, sizeof dh);
    return CAIRN_OK;
}

/* ------------------------------------------------------------------- seal */

int cairn_session_seal(const cairn_session *cs, cairn_header *hdr,
                       uint8_t *out, size_t outcap, size_t *outlen,
                       const void *plaintext, size_t plaintextlen)
{
    cairn_session *s = (cairn_session *)cs;
    uint8_t key[CAIRN_KEY_BYTES];
    uint8_t next[CAIRN_KEY_BYTES];
    uint8_t nonce[CAIRN_NONCE_BYTES];
    uint8_t aad[HEADER_BYTES];
    int rc;

    if (s == NULL || hdr == NULL || out == NULL || outlen == NULL) return CAIRN_ERR_ARG;
    if (plaintext == NULL && plaintextlen > 0) return CAIRN_ERR_ARG;
    if (!s->established) return CAIRN_ERR_STATE;
    if (outcap < plaintextlen + CAIRN_TAG_BYTES) return CAIRN_ERR_BUFFER;

    /* A full chain means it is time for a new ratchet key. */
    if (s->sent_in_chain >= CAIRN_RATCHET_INTERVAL) {
        rc = ratchet_send_step(s);
        if (rc != CAIRN_OK) return rc;
    }

    hdr->epoch = s->send_epoch;
    hdr->index = s->send_index;
    memcpy(hdr->dh_pub, s->send_dh_pub, CAIRN_X25519_BYTES);

    advance_chain(next, key, s->send_chain);
    memcpy(s->send_chain, next, CAIRN_KEY_BYTES);
    s->send_index++;
    s->sent_in_chain++;

    message_nonce(nonce, hdr->epoch, hdr->index);
    header_aad(aad, hdr);
    cairn_aead_seal(out, key, nonce, aad, sizeof aad, plaintext, plaintextlen);

    *outlen = plaintextlen + CAIRN_TAG_BYTES;
    cairn_memzero(key, sizeof key);
    cairn_memzero(next, sizeof next);
    return CAIRN_OK;
}

/* ------------------------------------------------------------------- open */

static int skipped_store(cairn_session *s, uint32_t epoch, uint32_t index,
                         const uint8_t key[CAIRN_KEY_BYTES])
{
    int i;

    for (i = 0; i < CAIRN_MAX_SKIPPED; i++) {
        if (!s->skipped[i].used) {
            s->skipped[i].used = 1;
            s->skipped[i].epoch = epoch;
            s->skipped[i].index = index;
            memcpy(s->skipped[i].key, key, CAIRN_KEY_BYTES);
            return CAIRN_OK;
        }
    }
    /* The table is full: drop the message rather than evicting a live key, so
     * an attacker cannot flush keys by sending many future messages. */
    return CAIRN_ERR_BUFFER;
}

static int skipped_take(cairn_session *s, uint32_t epoch, uint32_t index,
                        uint8_t key[CAIRN_KEY_BYTES])
{
    int i;

    for (i = 0; i < CAIRN_MAX_SKIPPED; i++) {
        if (s->skipped[i].used && s->skipped[i].epoch == epoch &&
            s->skipped[i].index == index) {
            memcpy(key, s->skipped[i].key, CAIRN_KEY_BYTES);
            cairn_memzero(&s->skipped[i], sizeof s->skipped[i]);
            s->skipped[i].used = 0;
            return CAIRN_OK;
        }
    }
    return CAIRN_ERR_NOT_FOUND;
}

int cairn_session_open(cairn_session *s, const cairn_header *hdr,
                       uint8_t *out, size_t outcap, size_t *outlen,
                       const void *ciphertext, size_t ciphertextlen)
{
    uint8_t key[CAIRN_KEY_BYTES];
    uint8_t next[CAIRN_KEY_BYTES];
    uint8_t nonce[CAIRN_NONCE_BYTES];
    uint8_t aad[HEADER_BYTES];
    int rc;

    if (s == NULL || hdr == NULL || out == NULL || outlen == NULL) return CAIRN_ERR_ARG;
    if (!s->established) return CAIRN_ERR_STATE;
    if (ciphertext == NULL || ciphertextlen < CAIRN_TAG_BYTES) return CAIRN_ERR_FORMAT;
    if (outcap < ciphertextlen - CAIRN_TAG_BYTES) return CAIRN_ERR_BUFFER;

    header_aad(aad, hdr);
    message_nonce(nonce, hdr->epoch, hdr->index);

    /* A key from an earlier chain that arrived late. */
    rc = skipped_take(s, hdr->epoch, hdr->index, key);
    if (rc == CAIRN_OK) {
        rc = cairn_aead_open(out, key, nonce, aad, sizeof aad, ciphertext, ciphertextlen);
        cairn_memzero(key, sizeof key);
        if (rc != CAIRN_OK) return CAIRN_ERR_AUTH;
        *outlen = ciphertextlen - CAIRN_TAG_BYTES;
        return CAIRN_OK;
    }

    /* A new ratchet key means the peer stepped; mirror the step first. */
    if (memcmp(hdr->dh_pub, s->recv_dh_pub, CAIRN_X25519_BYTES) != 0) {
        rc = ratchet_recv_step(s, hdr->dh_pub);
        if (rc != CAIRN_OK) return CAIRN_ERR_AUTH;
    }

    /* Anything older than the current index within this chain is a replay. */
    if (hdr->epoch == s->recv_epoch && hdr->index < s->recv_index)
        return CAIRN_ERR_REPLAY;

    /* Walk the chain forward to the message index, keeping the skipped keys so a
     * delayed message can still be opened later. */
    while (s->recv_index < hdr->index) {
        advance_chain(next, key, s->recv_chain);
        memcpy(s->recv_chain, next, CAIRN_KEY_BYTES);
        if (skipped_store(s, s->recv_epoch, s->recv_index, key) != CAIRN_OK) {
            cairn_memzero(key, sizeof key);
            return CAIRN_ERR_BUFFER;
        }
        s->recv_index++;
    }

    advance_chain(next, key, s->recv_chain);
    memcpy(s->recv_chain, next, CAIRN_KEY_BYTES);
    s->recv_index++;

    rc = cairn_aead_open(out, key, nonce, aad, sizeof aad, ciphertext, ciphertextlen);
    cairn_memzero(key, sizeof key);
    if (rc != CAIRN_OK) return CAIRN_ERR_AUTH;

    *outlen = ciphertextlen - CAIRN_TAG_BYTES;
    return CAIRN_OK;
}

void cairn_session_clear(cairn_session *s)
{
    if (s != NULL) cairn_memzero(s, sizeof *s);
}