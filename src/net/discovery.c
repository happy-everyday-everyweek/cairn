/* cairn: beacon encoding and the neighbour table. */
#include "cairn/discovery.h"

#include <string.h>

#define FIXED_BYTES (2 + 1 + 1 + CAIRN_ID_BYTES + 16 + 2 + 1)

static void put_u16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
}

static uint16_t get_u16(const uint8_t *p)
{
    return (uint16_t)(p[0] | ((uint16_t)p[1] << 8));
}

int cairn_beacon_encode(uint8_t *out, size_t outcap, size_t *outlen,
                        const cairn_beacon *b)
{
    size_t namelen, need, o = 0;

    if (out == NULL || outlen == NULL || b == NULL) return CAIRN_ERR_ARG;

    namelen = strlen(b->name);
    if (namelen > CAIRN_NAME_MAX) namelen = CAIRN_NAME_MAX;
    need = FIXED_BYTES + namelen;
    if (outcap < need) return CAIRN_ERR_BUFFER;

    out[o++] = CAIRN_BEACON_MAGIC0;
    out[o++] = CAIRN_BEACON_MAGIC1;
    out[o++] = CAIRN_BEACON_VERSION;
    out[o++] = b->capabilities;
    memcpy(out + o, b->id, CAIRN_ID_BYTES);
    o += CAIRN_ID_BYTES;
    memcpy(out + o, b->fp_prefix, 16);
    o += 16;
    put_u16(out + o, b->port);
    o += 2;
    out[o++] = (uint8_t)namelen;
    if (namelen > 0) memcpy(out + o, b->name, namelen);
    o += namelen;

    *outlen = o;
    return CAIRN_OK;
}

int cairn_beacon_decode(cairn_beacon *b, const void *buf, size_t len)
{
    const uint8_t *p = (const uint8_t *)buf;
    size_t namelen, o = 0;

    if (b == NULL || buf == NULL) return CAIRN_ERR_ARG;
    if (len < FIXED_BYTES) return CAIRN_ERR_FORMAT;
    if (p[0] != CAIRN_BEACON_MAGIC0 || p[1] != CAIRN_BEACON_MAGIC1)
        return CAIRN_ERR_FORMAT;
    if (p[2] != CAIRN_BEACON_VERSION) return CAIRN_ERR_FORMAT;

    memset(b, 0, sizeof *b);
    b->capabilities = p[3];
    o = 4;
    memcpy(b->id, p + o, CAIRN_ID_BYTES);
    o += CAIRN_ID_BYTES;
    memcpy(b->fp_prefix, p + o, 16);
    o += 16;
    b->port = get_u16(p + o);
    o += 2;

    namelen = p[o++];
    /* The declared name must fit both the cap and the bytes actually present,
     * otherwise a peer could claim a name longer than its packet. */
    if (namelen > CAIRN_NAME_MAX) return CAIRN_ERR_FORMAT;
    if (len < o + namelen) return CAIRN_ERR_FORMAT;
    if (namelen > 0) memcpy(b->name, p + o, namelen);
    b->name[namelen] = '\0';
    return CAIRN_OK;
}

int cairn_beacon_from_identity(cairn_beacon *b, const cairn_identity *id,
                               const char *name, uint16_t port,
                               uint8_t capabilities)
{
    uint8_t fp[CAIRN_FP_BYTES];
    size_t namelen;
    int rc;

    if (b == NULL || id == NULL) return CAIRN_ERR_ARG;

    rc = cairn_identity_fingerprint(fp, id);
    if (rc != CAIRN_OK) return rc;

    memset(b, 0, sizeof *b);
    memcpy(b->id, id->id, CAIRN_ID_BYTES);
    memcpy(b->fp_prefix, fp, 16);
    b->port = port;
    b->capabilities = capabilities;

    if (name != NULL) {
        namelen = strlen(name);
        if (namelen > CAIRN_NAME_MAX) namelen = CAIRN_NAME_MAX;
        memcpy(b->name, name, namelen);
        b->name[namelen] = '\0';
    }
    return CAIRN_OK;
}

int cairn_neighbours_add(cairn_neighbours *n, const cairn_beacon *b, uint32_t now_ms)
{
    int i;

    if (n == NULL || b == NULL) return CAIRN_ERR_ARG;

    for (i = 0; i < n->count; i++) {
        if (memcmp(n->entries[i].id, b->id, CAIRN_ID_BYTES) == 0) {
            n->entries[i] = *b;
            n->last_seen_ms[i] = now_ms;
            return CAIRN_OK;
        }
    }

    if (n->count >= CAIRN_NEIGHBOURS_MAX) return CAIRN_ERR_MEMORY;
    n->entries[n->count] = *b;
    n->last_seen_ms[n->count] = now_ms;
    n->count++;
    return CAIRN_OK;
}

int cairn_neighbours_find(const cairn_neighbours *n, const uint8_t id[CAIRN_ID_BYTES])
{
    int i;

    if (n == NULL || id == NULL) return CAIRN_ERR_ARG;
    for (i = 0; i < n->count; i++)
        if (memcmp(n->entries[i].id, id, CAIRN_ID_BYTES) == 0) return i;
    return CAIRN_ERR_NOT_FOUND;
}

int cairn_neighbours_expire(cairn_neighbours *n, uint32_t now_ms, uint32_t ttl_ms)
{
    int i, keep = 0;

    if (n == NULL) return CAIRN_ERR_ARG;

    for (i = 0; i < n->count; i++) {
        /* Unsigned subtraction handles a clock wrap without a special case. */
        uint32_t age = now_ms - n->last_seen_ms[i];
        if (age <= ttl_ms) {
            if (keep != i) {
                n->entries[keep] = n->entries[i];
                n->last_seen_ms[keep] = n->last_seen_ms[i];
            }
            keep++;
        }
    }
    n->count = keep;
    return CAIRN_OK;
}

void cairn_neighbours_clear(cairn_neighbours *n)
{
    if (n != NULL) {
        memset(n->entries, 0, sizeof n->entries);
        memset(n->last_seen_ms, 0, sizeof n->last_seen_ms);
        n->count = 0;
    }
}