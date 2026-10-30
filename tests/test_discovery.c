#include "test.h"

#include <string.h>

#include "cairn/discovery.h"

static void make_beacon(cairn_beacon *b, uint8_t seed, const char *name)
{
    memset(b, 0, sizeof *b);
    memset(b->id, seed, sizeof b->id);
    memset(b->fp_prefix, (uint8_t)(seed + 1), sizeof b->fp_prefix);
    b->port = (uint16_t)(9000 + seed);
    b->capabilities = (uint8_t)(CAIRN_CAP_TRANSFER | CAIRN_CAP_CHAT);
    strncpy(b->name, name, CAIRN_NAME_MAX);
    b->name[CAIRN_NAME_MAX] = '\0';
}

CT_TEST(beacon_roundtrip)
{
    cairn_beacon in, out;
    uint8_t wire[CAIRN_BEACON_MAX];
    size_t len = 0;

    make_beacon(&in, 0x11, "alice-phone");
    CT_ASSERT_EQ_INT(cairn_beacon_encode(wire, sizeof wire, &len, &in), CAIRN_OK);
    CT_ASSERT(len > 0 && len <= CAIRN_BEACON_MAX);

    memset(&out, 0, sizeof out);
    CT_ASSERT_EQ_INT(cairn_beacon_decode(&out, wire, len), CAIRN_OK);
    CT_ASSERT_MEM_EQ(in.id, out.id, CAIRN_ID_BYTES);
    CT_ASSERT_MEM_EQ(in.fp_prefix, out.fp_prefix, 16);
    CT_ASSERT_EQ_INT(out.port, in.port);
    CT_ASSERT_EQ_INT(out.capabilities, in.capabilities);
    CT_ASSERT_EQ_INT((int)strlen(out.name), (int)strlen(in.name));
    CT_ASSERT_MEM_EQ(in.name, out.name, strlen(in.name));
}

/* An empty name is legal: a device may not want to broadcast a host name. */
CT_TEST(beacon_empty_name)
{
    cairn_beacon in, out;
    uint8_t wire[CAIRN_BEACON_MAX];
    size_t len = 0;

    make_beacon(&in, 0x22, "");
    CT_ASSERT_EQ_INT(cairn_beacon_encode(wire, sizeof wire, &len, &in), CAIRN_OK);
    CT_ASSERT_EQ_INT(cairn_beacon_decode(&out, wire, len), CAIRN_OK);
    CT_ASSERT_EQ_INT(out.name[0], '\0');
}

/* Every truncation and a bad magic must be refused. */
CT_TEST(beacon_bad_input_rejected)
{
    cairn_beacon in, out;
    uint8_t wire[CAIRN_BEACON_MAX];
    size_t len = 0;
    size_t cut;

    make_beacon(&in, 0x33, "bob");
    CT_ASSERT_EQ_INT(cairn_beacon_encode(wire, sizeof wire, &len, &in), CAIRN_OK);

    for (cut = 0; cut < len; cut++)
        CT_ASSERT(cairn_beacon_decode(&out, wire, cut) != CAIRN_OK);

    wire[0] ^= 0xff;
    CT_ASSERT_EQ_INT(cairn_beacon_decode(&out, wire, len), CAIRN_ERR_FORMAT);
}

/* A name length field longer than the buffer must not be trusted. */
CT_TEST(beacon_lying_name_length_rejected)
{
    cairn_beacon in, out;
    uint8_t wire[CAIRN_BEACON_MAX];
    size_t len = 0;

    make_beacon(&in, 0x44, "carol");
    CT_ASSERT_EQ_INT(cairn_beacon_encode(wire, sizeof wire, &len, &in), CAIRN_OK);

    /* name_len lives right before the name bytes. */
    wire[len - strlen("carol") - 1] = 0xff;
    CT_ASSERT_EQ_INT(cairn_beacon_decode(&out, wire, len), CAIRN_ERR_FORMAT);
}

/* A name longer than the maximum is truncated, not rejected. */
CT_TEST(beacon_long_name_truncated)
{
    cairn_beacon in, out;
    uint8_t wire[CAIRN_BEACON_MAX];
    size_t len = 0;
    char long_name[100];

    memset(long_name, 'x', sizeof long_name - 1);
    long_name[sizeof long_name - 1] = '\0';

    make_beacon(&in, 0x55, long_name);
    CT_ASSERT_EQ_INT(cairn_beacon_encode(wire, sizeof wire, &len, &in), CAIRN_OK);
    CT_ASSERT_EQ_INT(cairn_beacon_decode(&out, wire, len), CAIRN_OK);
    CT_ASSERT_EQ_INT((int)strlen(out.name), CAIRN_NAME_MAX);
}

CT_TEST(beacon_from_identity)
{
    cairn_identity id;
    cairn_beacon b;
    uint8_t fp[CAIRN_FP_BYTES];

    CT_ASSERT_EQ_INT(cairn_identity_generate(&id), CAIRN_OK);
    CT_ASSERT_EQ_INT(cairn_beacon_from_identity(&b, &id, "pixel", 7777,
                                                CAIRN_CAP_TRANSFER), CAIRN_OK);
    CT_ASSERT_EQ_INT(b.port, 7777);
    CT_ASSERT_EQ_INT(b.capabilities, CAIRN_CAP_TRANSFER);
    CT_ASSERT_MEM_EQ(b.id, id.id, CAIRN_ID_BYTES);

    /* The prefix must match the first bytes of the full fingerprint, so a peer
     * that later gets the full key can verify the advertisement. */
    CT_ASSERT_EQ_INT(cairn_identity_fingerprint(fp, &id), CAIRN_OK);
    CT_ASSERT_MEM_EQ(b.fp_prefix, fp, 16);

    cairn_identity_clear(&id);
}

/* A device that has already seen a beacon must update, not duplicate. */
CT_TEST(neighbours_add_and_update)
{
    cairn_neighbours table;
    cairn_beacon b;

    memset(&table, 0, sizeof table);
    make_beacon(&b, 0x66, "dave");
    CT_ASSERT_EQ_INT(cairn_neighbours_add(&table, &b, 1000), CAIRN_OK);
    CT_ASSERT_EQ_INT(table.count, 1);

    CT_ASSERT_EQ_INT(cairn_neighbours_add(&table, &b, 2000), CAIRN_OK);
    CT_ASSERT_EQ_INT(table.count, 1);
    CT_ASSERT_EQ_INT(table.last_seen_ms[0], 2000);

    b.port = 1234;
    CT_ASSERT_EQ_INT(cairn_neighbours_add(&table, &b, 3000), CAIRN_OK);
    CT_ASSERT_EQ_INT(table.count, 1);
    CT_ASSERT_EQ_INT(table.entries[0].port, 1234);
}

CT_TEST(neighbours_find_by_id)
{
    cairn_neighbours table;
    cairn_beacon a, b;
    int idx;

    memset(&table, 0, sizeof table);
    make_beacon(&a, 0x77, "eve");
    make_beacon(&b, 0x88, "frank");
    CT_ASSERT_EQ_INT(cairn_neighbours_add(&table, &a, 1000), CAIRN_OK);
    CT_ASSERT_EQ_INT(cairn_neighbours_add(&table, &b, 1000), CAIRN_OK);

    idx = cairn_neighbours_find(&table, a.id);
    CT_ASSERT(idx >= 0 && idx < 2);
    CT_ASSERT_MEM_EQ(table.entries[idx].id, a.id, CAIRN_ID_BYTES);
    idx = cairn_neighbours_find(&table, b.id);
    CT_ASSERT(idx >= 0 && idx < 2);
    CT_ASSERT_MEM_EQ(table.entries[idx].id, b.id, CAIRN_ID_BYTES);

    b.id[0] ^= 0xff;
    CT_ASSERT_EQ_INT(cairn_neighbours_find(&table, b.id), CAIRN_ERR_NOT_FOUND);
}

/* Stale entries must disappear so a table cannot fill with ghosts. */
CT_TEST(neighbours_expire)
{
    cairn_neighbours table;
    cairn_beacon a, b;

    memset(&table, 0, sizeof table);
    make_beacon(&a, 0x99, "gina");
    make_beacon(&b, 0xaa, "hank");
    CT_ASSERT_EQ_INT(cairn_neighbours_add(&table, &a, 1000), CAIRN_OK);
    CT_ASSERT_EQ_INT(cairn_neighbours_add(&table, &b, 20000), CAIRN_OK);

    /* a is 19000 ms old, b is 0 ms old, ttl 10000. */
    CT_ASSERT_EQ_INT(cairn_neighbours_expire(&table, 20000, 10000), CAIRN_OK);
    CT_ASSERT_EQ_INT(table.count, 1);
    CT_ASSERT(cairn_neighbours_find(&table, b.id) >= 0);
    CT_ASSERT_EQ_INT(cairn_neighbours_find(&table, a.id), CAIRN_ERR_NOT_FOUND);
}

/* A full table must report the failure instead of overwriting a live peer. */
CT_TEST(neighbours_full_reports)
{
    cairn_neighbours table;
    cairn_beacon b;
    int i;

    memset(&table, 0, sizeof table);
    for (i = 0; i < CAIRN_NEIGHBOURS_MAX; i++) {
        make_beacon(&b, (uint8_t)i, "peer");
        CT_ASSERT_EQ_INT(cairn_neighbours_add(&table, &b, 1000), CAIRN_OK);
    }
    make_beacon(&b, 0xfe, "extra");
    CT_ASSERT_EQ_INT(cairn_neighbours_add(&table, &b, 1000), CAIRN_ERR_MEMORY);
    CT_ASSERT_EQ_INT(table.count, CAIRN_NEIGHBOURS_MAX);

    cairn_neighbours_clear(&table);
    CT_ASSERT_EQ_INT(table.count, 0);
}

/* An expired peer must free a slot for a new one. */
CT_TEST(neighbours_slot_reused_after_expire)
{
    cairn_neighbours table;
    cairn_beacon b;
    int i;

    memset(&table, 0, sizeof table);
    for (i = 0; i < CAIRN_NEIGHBOURS_MAX; i++) {
        make_beacon(&b, (uint8_t)i, "peer");
        CT_ASSERT_EQ_INT(cairn_neighbours_add(&table, &b, 0), CAIRN_OK);
    }
    CT_ASSERT_EQ_INT(cairn_neighbours_expire(&table, 100000, 1000), CAIRN_OK);
    CT_ASSERT_EQ_INT(table.count, 0);

    make_beacon(&b, 0xfd, "newcomer");
    CT_ASSERT_EQ_INT(cairn_neighbours_add(&table, &b, 100000), CAIRN_OK);
    CT_ASSERT_EQ_INT(table.count, 1);
}

void ct_reg_discovery(void)
{
    CT_REG(beacon_roundtrip);
    CT_REG(beacon_empty_name);
    CT_REG(beacon_bad_input_rejected);
    CT_REG(beacon_lying_name_length_rejected);
    CT_REG(beacon_long_name_truncated);
    CT_REG(beacon_from_identity);
    CT_REG(neighbours_add_and_update);
    CT_REG(neighbours_find_by_id);
    CT_REG(neighbours_expire);
    CT_REG(neighbours_full_reports);
    CT_REG(neighbours_slot_reused_after_expire);
}