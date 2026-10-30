#include "test.h"

#include <string.h>

#include "cairn/p2p.h"

/* A fake Wi-Fi Direct stack: enough to exercise the state machine that ships. */
typedef struct {
    int discover_calls;
    int stop_calls;
    int connect_calls;
    int disconnect_calls;
    cairn_p2p_peer_cb peer_cb;
    void *peer_user;
    cairn_p2p_group_cb group_cb;
    void *group_user;
    char owner_addr[CAIRN_P2P_ADDR_BYTES];
    const char *owner;
    int fail_next;
} fake_p2p;

static int p_discover(void *impl, cairn_p2p_peer_cb cb, void *user)
{
    fake_p2p *f = (fake_p2p *)impl;
    if (f->fail_next) return CAIRN_ERR_IO;
    f->peer_cb = cb;
    f->peer_user = user;
    f->discover_calls++;
    return CAIRN_OK;
}

static int p_stop(void *impl)
{
    fake_p2p *f = (fake_p2p *)impl;
    f->stop_calls++;
    return CAIRN_OK;
}

static int p_connect(void *impl, const uint8_t addr[6], cairn_p2p_group_cb cb, void *user)
{
    fake_p2p *f = (fake_p2p *)impl;
    if (f->fail_next) return CAIRN_ERR_TIMEOUT;
    f->group_cb = cb;
    f->group_user = user;
    f->connect_calls++;
    (void)addr;
    return CAIRN_OK;
}

static int p_disconnect(void *impl)
{
    fake_p2p *f = (fake_p2p *)impl;
    f->disconnect_calls++;
    f->owner = NULL;
    return CAIRN_OK;
}

static const char *p_owner(void *impl)
{
    fake_p2p *f = (fake_p2p *)impl;
    return f->owner;
}

static const cairn_p2p_ops kFakeOps = {
    p_discover, p_stop, p_connect, p_disconnect, p_owner
};

CT_TEST(p2p_init_requires_ops)
{
    cairn_p2p p;
    fake_p2p f;

    memset(&f, 0, sizeof f);
    CT_ASSERT_EQ_INT(cairn_p2p_init(NULL, &kFakeOps, &f), CAIRN_ERR_ARG);
    CT_ASSERT_EQ_INT(cairn_p2p_init(&p, NULL, &f), CAIRN_ERR_ARG);
    {
        cairn_p2p_ops empty;
        memset(&empty, 0, sizeof empty);
        CT_ASSERT_EQ_INT(cairn_p2p_init(&p, &empty, &f), CAIRN_ERR_UNSUPPORTED);
    }
    CT_ASSERT_EQ_INT(cairn_p2p_init(&p, &kFakeOps, &f), CAIRN_OK);
    CT_ASSERT_EQ_INT(cairn_p2p_state_of(&p), CAIRN_P2P_IDLE);
}

CT_TEST(p2p_discover_lifecycle)
{
    cairn_p2p p;
    fake_p2p f;

    memset(&f, 0, sizeof f);
    CT_ASSERT_EQ_INT(cairn_p2p_init(&p, &kFakeOps, &f), CAIRN_OK);
    CT_ASSERT_EQ_INT(cairn_p2p_discover(&p, NULL, NULL), CAIRN_OK);
    CT_ASSERT_EQ_INT(f.discover_calls, 1);
    CT_ASSERT_EQ_INT(cairn_p2p_state_of(&p), CAIRN_P2P_DISCOVERING);
    CT_ASSERT_EQ_INT(cairn_p2p_stop_discover(&p), CAIRN_OK);
    CT_ASSERT_EQ_INT(f.stop_calls, 1);
    CT_ASSERT_EQ_INT(cairn_p2p_state_of(&p), CAIRN_P2P_IDLE);
}

CT_TEST(p2p_connect_requires_address)
{
    cairn_p2p p;
    fake_p2p f;

    memset(&f, 0, sizeof f);
    CT_ASSERT_EQ_INT(cairn_p2p_init(&p, &kFakeOps, &f), CAIRN_OK);
    /* Not connected, so there is nothing to dial. */
    CT_ASSERT(cairn_p2p_address(&p) == NULL);
    CT_ASSERT_EQ_INT(cairn_p2p_connect(&p, (const uint8_t *)"\1\2\3\4\5\6", NULL, NULL),
                     CAIRN_OK);
    CT_ASSERT_EQ_INT(cairn_p2p_state_of(&p), CAIRN_P2P_NEGOTIATING);
    CT_ASSERT(cairn_p2p_address(&p) == NULL);
    CT_ASSERT_EQ_INT(cairn_p2p_disconnect(&p), CAIRN_OK);
    CT_ASSERT_EQ_INT(f.disconnect_calls, 1);
    CT_ASSERT_EQ_INT(cairn_p2p_state_of(&p), CAIRN_P2P_IDLE);
}

/* A failed discovery must not leave the handle claiming to search. */
CT_TEST(p2p_failure_surfaces)
{
    cairn_p2p p;
    fake_p2p f;

    memset(&f, 0, sizeof f);
    CT_ASSERT_EQ_INT(cairn_p2p_init(&p, &kFakeOps, &f), CAIRN_OK);
    f.fail_next = 1;
    CT_ASSERT_EQ_INT(cairn_p2p_discover(&p, NULL, NULL), CAIRN_ERR_IO);
    CT_ASSERT_EQ_INT(cairn_p2p_state_of(&p), CAIRN_P2P_ERROR);

    f.fail_next = 0;
    CT_ASSERT_EQ_INT(cairn_p2p_connect(&p, (const uint8_t *)"\1\2\3\4\5\6", NULL, NULL),
                     CAIRN_ERR_STATE);
}

void ct_reg_p2p(void)
{
    CT_REG(p2p_init_requires_ops);
    CT_REG(p2p_discover_lifecycle);
    CT_REG(p2p_connect_requires_address);
    CT_REG(p2p_failure_surfaces);
}