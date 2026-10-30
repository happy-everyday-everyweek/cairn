/* cairn: platform independent Wi-Fi Direct (Wi-Fi P2P).
 *
 * Wi-Fi Direct is what makes Android to Android work without a router: one side
 * becomes the group owner, the other joins, and afterwards both have an IP
 * address on a private network. Everything above this layer then speaks ordinary
 * sockets.
 *
 * The vtable mirrors what the platform APIs actually expose: discover peers,
 * connect to form a group, learn the group owner's address, and leave. Group
 * owner negotiation is left to the platform because every implementation does it
 * differently and none of it changes the wire protocol.
 */
#ifndef CAIRN_P2P_H
#define CAIRN_P2P_H

#include <stddef.h>
#include <stdint.h>

#include "cairn/cairn.h"

#ifdef __cplusplus
extern "C" {
#endif

#define CAIRN_P2P_ADDR_BYTES 16
#define CAIRN_P2P_NAME_MAX 32
#define CAIRN_P2P_MAX_PEERS 16

typedef struct {
    uint8_t addr[6];
    char name[CAIRN_P2P_NAME_MAX + 1];
    int is_group_owner;
} cairn_p2p_peer;

typedef enum {
    CAIRN_P2P_IDLE = 0,
    CAIRN_P2P_DISCOVERING = 1,
    CAIRN_P2P_NEGOTIATING = 2,
    CAIRN_P2P_CONNECTED = 3,
    CAIRN_P2P_ERROR = 4
} cairn_p2p_state;

/* Called for each peer found during discovery. */
typedef void (*cairn_p2p_peer_cb)(void *user, const cairn_p2p_peer *peer);

/* Called when group formation finishes. addr is the group owner address in
 * presentation form, for example "192.168.49.1", or NULL on failure. */
typedef void (*cairn_p2p_group_cb)(void *user, const char *addr, int is_owner,
                                   int status);

typedef struct {
    int (*discover)(void *impl, cairn_p2p_peer_cb cb, void *user);
    int (*stop_discover)(void *impl);
    int (*connect)(void *impl, const uint8_t addr[6], cairn_p2p_group_cb cb, void *user);
    int (*disconnect)(void *impl);
    /* Address of the group owner once connected; NULL when not connected. */
    const char *(*group_owner_address)(void *impl);
} cairn_p2p_ops;

typedef struct {
    const cairn_p2p_ops *ops;
    void *impl;
    cairn_p2p_state state;
} cairn_p2p;

int cairn_p2p_init(cairn_p2p *p, const cairn_p2p_ops *ops, void *impl);

int cairn_p2p_discover(cairn_p2p *p, cairn_p2p_peer_cb cb, void *user);
int cairn_p2p_stop_discover(cairn_p2p *p);

/* Forms or joins a group with the chosen peer. */
int cairn_p2p_connect(cairn_p2p *p, const uint8_t addr[6],
                      cairn_p2p_group_cb cb, void *user);
int cairn_p2p_disconnect(cairn_p2p *p);

/* The address to dial, or NULL. Valid only while connected. */
const char *cairn_p2p_address(const cairn_p2p *p);

cairn_p2p_state cairn_p2p_state_of(const cairn_p2p *p);

#ifdef __cplusplus
}
#endif

#endif /* CAIRN_P2P_H */