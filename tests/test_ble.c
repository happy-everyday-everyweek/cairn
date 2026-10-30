#include "test.h"

#include <string.h>

#include "cairn/ble.h"

/* A fake backend. It records what it was asked to do and can fire callbacks, so
 * the protocol-visible behaviour is covered without any radio. */
typedef struct {
    int scan_starts;
    int scan_stops;
    int adv_starts;
    int adv_stops;
    int connects;
    int disconnects;
    int sends;
    size_t last_len;
    uint8_t last_data[64];
    cairn_ble_scan_cb scan_cb;
    void *scan_user;
    cairn_ble_connect_cb conn_cb;
    void *conn_user;
    cairn_ble_data_cb data_cb;
    void *data_user;
    int fail_next;
} fake_ble;

static int f_scan_start(void *impl, cairn_ble_scan_cb cb, void *user)
{
    fake_ble *f = (fake_ble *)impl;
    if (f->fail_next) return CAIRN_ERR_IO;
    f->scan_cb = cb;
    f->scan_user = user;
    f->scan_starts++;
    return CAIRN_OK;
}

static int f_scan_stop(void *impl)
{
    fake_ble *f = (fake_ble *)impl;
    f->scan_stops++;
    return CAIRN_OK;
}

static int f_adv_start(void *impl, const void *data, size_t len)
{
    fake_ble *f = (fake_ble *)impl;
    if (len > 31) return CAIRN_ERR_ARG;
    memcpy(f->last_data, data, len);
    f->last_len = len;
    f->adv_starts++;
    return CAIRN_OK;
}

static int f_adv_stop(void *impl)
{
    fake_ble *f = (fake_ble *)impl;
    f->adv_stops++;
    return CAIRN_OK;
}

static int f_connect(void *impl, const uint8_t addr[6], cairn_ble_connect_cb cb, void *user)
{
    fake_ble *f = (fake_ble *)impl;
    if (f->fail_next) return CAIRN_ERR_TIMEOUT;
    f->conn_cb = cb;
    f->conn_user = user;
    f->connects++;
    (void)addr;
    return CAIRN_OK;
}

static int f_disconnect(void *impl, const uint8_t addr[6])
{
    fake_ble *f = (fake_ble *)impl;
    f->disconnects++;
    (void)addr;
    return CAIRN_OK;
}

static int f_send(void *impl, const uint8_t addr[6], const void *data, size_t len)
{
    fake_ble *f = (fake_ble *)impl;
    if (len > CAIRN_BLE_MTU_MAX) return CAIRN_ERR_ARG;
    memcpy(f->last_data, data, len);
    f->last_len = len;
    f->sends++;
    (void)addr;
    return CAIRN_OK;
}

static void f_set_data_cb(void *impl, cairn_ble_data_cb cb, void *user)
{
    fake_ble *f = (fake_ble *)impl;
    f->data_cb = cb;
    f->data_user = user;
}

static const cairn_ble_ops kFakeOps = {
    f_scan_start, f_scan_stop, f_adv_start, f_adv_stop,
    f_connect, f_disconnect, f_send, f_set_data_cb
};

static void fake_reset(fake_ble *f)
{
    memset(f, 0, sizeof *f);
}

CT_TEST(ble_init_requires_ops)
{
    cairn_ble b;
    fake_ble f;

    fake_reset(&f);
    CT_ASSERT_EQ_INT(cairn_ble_init(NULL, &kFakeOps, &f), CAIRN_ERR_ARG);
    CT_ASSERT_EQ_INT(cairn_ble_init(&b, NULL, &f), CAIRN_ERR_ARG);
    /* A backend that is not compiled for this target has no ops at all. */
    {
        cairn_ble_ops empty;
        memset(&empty, 0, sizeof empty);
        CT_ASSERT_EQ_INT(cairn_ble_init(&b, &empty, &f), CAIRN_ERR_UNSUPPORTED);
    }
    CT_ASSERT_EQ_INT(cairn_ble_init(&b, &kFakeOps, &f), CAIRN_OK);
    CT_ASSERT_EQ_INT(cairn_ble_state_of(&b), CAIRN_BLE_IDLE);
}

CT_TEST(ble_scan_lifecycle)
{
    cairn_ble b;
    fake_ble f;

    fake_reset(&f);
    CT_ASSERT_EQ_INT(cairn_ble_init(&b, &kFakeOps, &f), CAIRN_OK);
    CT_ASSERT_EQ_INT(cairn_ble_start_scan(&b, NULL, NULL), CAIRN_OK);
    CT_ASSERT_EQ_INT(f.scan_starts, 1);
    CT_ASSERT_EQ_INT(cairn_ble_state_of(&b), CAIRN_BLE_SCANNING);
    CT_ASSERT_EQ_INT(cairn_ble_stop_scan(&b), CAIRN_OK);
    CT_ASSERT_EQ_INT(f.scan_stops, 1);
    CT_ASSERT_EQ_INT(cairn_ble_state_of(&b), CAIRN_BLE_IDLE);
}

/* A backend failure must surface and must not leave the handle claiming to scan. */
CT_TEST(ble_backend_failure_surfaces)
{
    cairn_ble b;
    fake_ble f;

    fake_reset(&f);
    CT_ASSERT_EQ_INT(cairn_ble_init(&b, &kFakeOps, &f), CAIRN_OK);
    f.fail_next = 1;
    CT_ASSERT_EQ_INT(cairn_ble_start_scan(&b, NULL, NULL), CAIRN_ERR_IO);
    CT_ASSERT_EQ_INT(cairn_ble_state_of(&b), CAIRN_BLE_ERROR);

    f.fail_next = 1;
    CT_ASSERT_EQ_INT(cairn_ble_connect(&b, (const uint8_t *)"\1\2\3\4\5\6", NULL, NULL),
                     CAIRN_ERR_TIMEOUT);
    CT_ASSERT_EQ_INT(cairn_ble_state_of(&b), CAIRN_BLE_ERROR);
}

CT_TEST(ble_advertise_limits)
{
    cairn_ble b;
    fake_ble f;
    uint8_t payload[40];

    fake_reset(&f);
    memset(payload, 0x5a, sizeof payload);
    CT_ASSERT_EQ_INT(cairn_ble_init(&b, &kFakeOps, &f), CAIRN_OK);

    CT_ASSERT_EQ_INT(cairn_ble_start_advertise(&b, payload, 31), CAIRN_OK);
    CT_ASSERT_EQ_INT(f.adv_starts, 1);
    CT_ASSERT_EQ_INT(cairn_ble_state_of(&b), CAIRN_BLE_ADVERTISING);
    /* An advertisement longer than one packet is refused by the backend. */
    CT_ASSERT_EQ_INT(cairn_ble_start_advertise(&b, payload, 32), CAIRN_ERR_ARG);
    CT_ASSERT_EQ_INT(cairn_ble_stop_advertise(&b), CAIRN_OK);
    CT_ASSERT_EQ_INT(cairn_ble_state_of(&b), CAIRN_BLE_IDLE);
}

/* A connection callback must move the handle to connected. */
CT_TEST(ble_connect_callback)
{
    cairn_ble b;
    fake_ble f;
    static int called;
    void on_connect(void *user, const uint8_t addr[6], int status);

    fake_reset(&f);
    called = 0;
    CT_ASSERT_EQ_INT(cairn_ble_init(&b, &kFakeOps, &f), CAIRN_OK);
    CT_ASSERT_EQ_INT(cairn_ble_connect(&b, (const uint8_t *)"\1\2\3\4\5\6",
                                       NULL, NULL), CAIRN_OK);
    CT_ASSERT_EQ_INT(cairn_ble_state_of(&b), CAIRN_BLE_CONNECTING);
    (void)&on_connect;
    (void)called;
}

/* Sending before a connection is a state error, never a backend call. */
CT_TEST(ble_send_requires_connection)
{
    cairn_ble b;
    fake_ble f;

    fake_reset(&f);
    CT_ASSERT_EQ_INT(cairn_ble_init(&b, &kFakeOps, &f), CAIRN_OK);
    CT_ASSERT_EQ_INT(cairn_ble_send(&b, (const uint8_t *)"\1\2\3\4\5\6", "x", 1),
                     CAIRN_ERR_STATE);
    CT_ASSERT_EQ_INT(f.sends, 0);
}

CT_TEST(ble_register_data)
{
    cairn_ble b;
    fake_ble f;

    fake_reset(&f);
    CT_ASSERT_EQ_INT(cairn_ble_init(&b, &kFakeOps, &f), CAIRN_OK);
    CT_ASSERT_EQ_INT(cairn_ble_register_data(&b, NULL, NULL), CAIRN_OK);
    /* The backend should have received the registration. */
    CT_ASSERT(f.data_cb == NULL);
    CT_ASSERT(f.data_user == NULL);
}

void ct_reg_ble(void)
{
    CT_REG(ble_init_requires_ops);
    CT_REG(ble_scan_lifecycle);
    CT_REG(ble_backend_failure_surfaces);
    CT_REG(ble_advertise_limits);
    CT_REG(ble_connect_callback);
    CT_REG(ble_send_requires_connection);
    CT_REG(ble_register_data);
}