/* cairn: platform independent Bluetooth Low Energy transport.
 *
 * There is no portable BLE API, so the library defines a small vtable and each
 * platform fills it in: BlueZ on Linux, WinRT on Windows, CoreBluetooth on
 * macOS, the Android BluetoothGatt stack on Android. The protocol above this
 * layer never learns which one is in use, which is also why the tests can drive
 * a fake implementation and cover the real state machine without hardware.
 *
 * Only what the protocol actually needs is here: scanning, advertising,
 * connecting and moving bytes on a characteristic. No pairing UI, no MTU
 * negotiation dance, no service caching. An application can do those itself,
 * and the judgement in docs/DESIGN.md says it should.
 */
#ifndef CAIRN_BLE_H
#define CAIRN_BLE_H

#include <stddef.h>
#include <stdint.h>

#include "cairn/cairn.h"

#ifdef __cplusplus
extern "C" {
#endif

/* A BLE characteristic write is 20 bytes by default and up to 512 with a long
 * write. Callers must treat this as the upper bound, not a guarantee. */
#define CAIRN_BLE_MTU_MIN 20
#define CAIRN_BLE_MTU_MAX 512

typedef enum {
    CAIRN_BLE_IDLE = 0,
    CAIRN_BLE_SCANNING = 1,
    CAIRN_BLE_ADVERTISING = 2,
    CAIRN_BLE_CONNECTING = 3,
    CAIRN_BLE_CONNECTED = 4,
    CAIRN_BLE_ERROR = 5
} cairn_ble_state;

typedef struct {
    uint8_t addr[6];
    int8_t rssi;
    uint8_t adv[31];
    size_t adv_len;
} cairn_ble_peer;

/* Called once per advertisement seen while scanning. */
typedef void (*cairn_ble_scan_cb)(void *user, const cairn_ble_peer *peer);

/* Called when a connection attempt finishes. */
typedef void (*cairn_ble_connect_cb)(void *user, const uint8_t addr[6], int status);

/* Called when the peer writes to our characteristic. */
typedef void (*cairn_ble_data_cb)(void *user, const uint8_t addr[6],
                                  const void *data, size_t len);

/* Backend operations. A target that does not support BLE leaves them NULL and
 * cairn_ble_init reports CAIRN_ERR_UNSUPPORTED. */
typedef struct {
    int (*start_scan)(void *impl, cairn_ble_scan_cb cb, void *user);
    int (*stop_scan)(void *impl);
    int (*start_advertise)(void *impl, const void *data, size_t len);
    int (*stop_advertise)(void *impl);
    int (*connect)(void *impl, const uint8_t addr[6], cairn_ble_connect_cb cb, void *user);
    int (*disconnect)(void *impl, const uint8_t addr[6]);
    int (*send)(void *impl, const uint8_t addr[6], const void *data, size_t len);
    void (*set_data_cb)(void *impl, cairn_ble_data_cb cb, void *user);
} cairn_ble_ops;

typedef struct cairn_ble {
    const cairn_ble_ops *ops;
    void *impl;
    cairn_ble_state state;
} cairn_ble;

/* Wires a backend into the handle. */
int cairn_ble_init(cairn_ble *b, const cairn_ble_ops *ops, void *impl);

int cairn_ble_start_scan(cairn_ble *b, cairn_ble_scan_cb cb, void *user);
int cairn_ble_stop_scan(cairn_ble *b);

int cairn_ble_start_advertise(cairn_ble *b, const void *data, size_t len);
int cairn_ble_stop_advertise(cairn_ble *b);

int cairn_ble_connect(cairn_ble *b, const uint8_t addr[6],
                      cairn_ble_connect_cb cb, void *user);
int cairn_ble_disconnect(cairn_ble *b, const uint8_t addr[6]);

/* Sends bytes to a connected peer. Returns CAIRN_ERR_STATE when not connected. */
int cairn_ble_send(cairn_ble *b, const uint8_t addr[6], const void *data, size_t len);

int cairn_ble_register_data(cairn_ble *b, cairn_ble_data_cb cb, void *user);

cairn_ble_state cairn_ble_state_of(const cairn_ble *b);

#ifdef __cplusplus
}
#endif

#endif /* CAIRN_BLE_H */