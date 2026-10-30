/* cairn: Wi-Fi Direct transport wrapper. */
#include "cairn/p2p.h"

#include <string.h>

int cairn_p2p_init(cairn_p2p *p, const cairn_p2p_ops *ops, void *impl)
{
    if (p == NULL || ops == NULL) return CAIRN_ERR_ARG;

    memset(p, 0, sizeof *p);
    if (ops->discover == NULL && ops->connect == NULL)
        return CAIRN_ERR_UNSUPPORTED;
    if (ops->discover == NULL || ops->connect == NULL || ops->group_owner_address == NULL)
        return CAIRN_ERR_ARG;

    p->ops = ops;
    p->impl = impl;
    p->state = CAIRN_P2P_IDLE;
    return CAIRN_OK;
}

int cairn_p2p_discover(cairn_p2p *p, cairn_p2p_peer_cb cb, void *user)
{
    int rc;

    if (p == NULL || p->ops == NULL) return CAIRN_ERR_ARG;
    /* Discovery is only meaningful from a settled state; searching while a group
     * is forming would race the platform's own state machine. */
    if (p->state == CAIRN_P2P_NEGOTIATING) return CAIRN_ERR_STATE;

    rc = p->ops->discover(p->impl, cb, user);
    p->state = rc == CAIRN_OK ? CAIRN_P2P_DISCOVERING : CAIRN_P2P_ERROR;
    return rc;
}

int cairn_p2p_stop_discover(cairn_p2p *p)
{
    int rc;

    if (p == NULL || p->ops == NULL) return CAIRN_ERR_ARG;
    if (p->ops->stop_discover == NULL) return CAIRN_ERR_UNSUPPORTED;
    rc = p->ops->stop_discover(p->impl);
    if (rc == CAIRN_OK && p->state == CAIRN_P2P_DISCOVERING) p->state = CAIRN_P2P_IDLE;
    return rc;
}

int cairn_p2p_connect(cairn_p2p *p, const uint8_t addr[6],
                      cairn_p2p_group_cb cb, void *user)
{
    int rc;

    if (p == NULL || p->ops == NULL || addr == NULL) return CAIRN_ERR_ARG;
    /* An errored handle has to be re-initialised rather than reused, so a caller
     * cannot accidentally treat a failed device as a usable one. */
    if (p->state == CAIRN_P2P_ERROR) return CAIRN_ERR_STATE;

    rc = p->ops->connect(p->impl, addr, cb, user);
    p->state = rc == CAIRN_OK ? CAIRN_P2P_NEGOTIATING : CAIRN_P2P_ERROR;
    return rc;
}

int cairn_p2p_disconnect(cairn_p2p *p)
{
    int rc;

    if (p == NULL || p->ops == NULL) return CAIRN_ERR_ARG;
    if (p->ops->disconnect == NULL) return CAIRN_ERR_UNSUPPORTED;
    rc = p->ops->disconnect(p->impl);
    if (rc == CAIRN_OK) p->state = CAIRN_P2P_IDLE;
    return rc;
}

const char *cairn_p2p_address(const cairn_p2p *p)
{
    if (p == NULL || p->ops == NULL) return NULL;
    if (p->state != CAIRN_P2P_CONNECTED) return NULL;
    return p->ops->group_owner_address(p->impl);
}

cairn_p2p_state cairn_p2p_state_of(const cairn_p2p *p)
{
    if (p == NULL) return CAIRN_P2P_ERROR;
    return p->state;
}