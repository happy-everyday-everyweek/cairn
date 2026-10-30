/* cairn: BLE transport wrapper.
 *
 * The state machine here is small on purpose. The platform owns radio details;
 * this layer's only job is to keep the handle's state honest, so a caller can
 * rely on cairn_ble_state_of without also watching backend return codes.
 */
#include "cairn/ble.h"

#include <string.h>

int cairn_ble_init(cairn_ble *b, const cairn_ble_ops *ops, void *impl)
{
    if (b == NULL || ops == NULL) return CAIRN_ERR_ARG;

    memset(b, 0, sizeof *b);
    /* A target without a BLE backend has an all-null table; report that clearly
     * so the node can pick another transport. */
    if (ops->start_scan == NULL && ops->connect == NULL && ops->send == NULL)
        return CAIRN_ERR_UNSUPPORTED;

    if (ops->start_scan == NULL || ops->connect == NULL || ops->send == NULL)
        return CAIRN_ERR_ARG;

    b->ops = ops;
    b->impl = impl;
    b->state = CAIRN_BLE_IDLE;
    return CAIRN_OK;
}

int cairn_ble_start_scan(cairn_ble *b, cairn_ble_scan_cb cb, void *user)
{
    int rc;

    if (b == NULL || b->ops == NULL) return CAIRN_ERR_ARG;
    rc = b->ops->start_scan(b->impl, cb, user);
    b->state = rc == CAIRN_OK ? CAIRN_BLE_SCANNING : CAIRN_BLE_ERROR;
    return rc;
}

int cairn_ble_stop_scan(cairn_ble *b)
{
    int rc;

    if (b == NULL || b->ops == NULL) return CAIRN_ERR_ARG;
    if (b->ops->stop_scan == NULL) return CAIRN_ERR_UNSUPPORTED;
    rc = b->ops->stop_scan(b->impl);
    if (rc == CAIRN_OK && b->state == CAIRN_BLE_SCANNING) b->state = CAIRN_BLE_IDLE;
    return rc;
}

int cairn_ble_start_advertise(cairn_ble *b, const void *data, size_t len)
{
    int rc;

    if (b == NULL || b->ops == NULL) return CAIRN_ERR_ARG;
    if (b->ops->start_advertise == NULL) return CAIRN_ERR_UNSUPPORTED;
    if (data == NULL && len > 0) return CAIRN_ERR_ARG;
    rc = b->ops->start_advertise(b->impl, data, len);
    if (rc == CAIRN_OK)
        b->state = CAIRN_BLE_ADVERTISING;
    else if (rc != CAIRN_ERR_ARG)
        b->state = CAIRN_BLE_ERROR;
    return rc;
}

int cairn_ble_stop_advertise(cairn_ble *b)
{
    int rc;

    if (b == NULL || b->ops == NULL) return CAIRN_ERR_ARG;
    if (b->ops->stop_advertise == NULL) return CAIRN_ERR_UNSUPPORTED;
    rc = b->ops->stop_advertise(b->impl);
    if (rc == CAIRN_OK && b->state == CAIRN_BLE_ADVERTISING) b->state = CAIRN_BLE_IDLE;
    return rc;
}

int cairn_ble_connect(cairn_ble *b, const uint8_t addr[6],
                      cairn_ble_connect_cb cb, void *user)
{
    int rc;

    if (b == NULL || b->ops == NULL || addr == NULL) return CAIRN_ERR_ARG;
    rc = b->ops->connect(b->impl, addr, cb, user);
    b->state = rc == CAIRN_OK ? CAIRN_BLE_CONNECTING : CAIRN_BLE_ERROR;
    return rc;
}

int cairn_ble_disconnect(cairn_ble *b, const uint8_t addr[6])
{
    int rc;

    if (b == NULL || b->ops == NULL || addr == NULL) return CAIRN_ERR_ARG;
    if (b->ops->disconnect == NULL) return CAIRN_ERR_UNSUPPORTED;
    rc = b->ops->disconnect(b->impl, addr);
    if (rc == CAIRN_OK) b->state = CAIRN_BLE_IDLE;
    return rc;
}

int cairn_ble_send(cairn_ble *b, const uint8_t addr[6], const void *data, size_t len)
{
    if (b == NULL || b->ops == NULL || addr == NULL) return CAIRN_ERR_ARG;
    if (data == NULL && len > 0) return CAIRN_ERR_ARG;
    /* Sending while not connected is a programming error, and calling into the
     * backend would only produce a less precise failure. */
    if (b->state != CAIRN_BLE_CONNECTED) return CAIRN_ERR_STATE;
    if (len > CAIRN_BLE_MTU_MAX) return CAIRN_ERR_ARG;
    return b->ops->send(b->impl, addr, data, len);
}

int cairn_ble_register_data(cairn_ble *b, cairn_ble_data_cb cb, void *user)
{
    if (b == NULL || b->ops == NULL) return CAIRN_ERR_ARG;
    if (b->ops->set_data_cb == NULL) return CAIRN_ERR_UNSUPPORTED;
    b->ops->set_data_cb(b->impl, cb, user);
    return CAIRN_OK;
}

cairn_ble_state cairn_ble_state_of(const cairn_ble *b)
{
    if (b == NULL) return CAIRN_BLE_ERROR;
    return b->state;
}