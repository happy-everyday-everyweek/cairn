#include "test.h"

#include <stdarg.h>

#define CT_MAX 256

static struct {
    const char *name;
    ct_fn fn;
} g_cases[CT_MAX];
static int g_count;
static int g_fail;
static int g_hit;

void ct_register(const char *name, ct_fn fn)
{
    if (g_count >= CT_MAX) return;
    g_cases[g_count].name = name;
    g_cases[g_count].fn = fn;
    g_count++;
}

void ct_failf(const char *file, int line, const char *fmt, ...)
{
    va_list ap;
    g_hit = 1;
    fprintf(stderr, "  %s:%d: ", file, line);
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
}

void ct_reg_blake2b(void);
void ct_reg_aead(void);
void ct_reg_dh(void);
void ct_reg_sign(void);
void ct_reg_kem(void);
void ct_reg_kdf(void);
void ct_reg_nested(void);
void ct_reg_identity(void);
void ct_reg_session(void);
void ct_reg_wire(void);
void ct_reg_transfer(void);
void ct_reg_nat(void);
void ct_reg_p2p(void);
void ct_reg_ble(void);
void ct_reg_discovery(void);
void ct_reg_bundle(void);
void ct_reg_pair(void);
void ct_reg_facade(void);
#ifndef CAIRN_NO_LIVE_PAIR
/* The two-node test needs two sockets and threads on one host, which Windows cannot
 * provide through this build. Everything else runs everywhere. */
void ct_reg_pair_live(void);
#endif
void ct_reg_pair_logic(void);
int main(void)
{
    int i, pass = 0;

    fprintf(stderr, "registering\n");
    ct_reg_blake2b();
    ct_reg_aead();
    ct_reg_dh();
    ct_reg_sign();
    ct_reg_kem();
    ct_reg_kdf();
    ct_reg_nested();
    ct_reg_identity();
    ct_reg_session();
    ct_reg_wire();
    ct_reg_transfer();
    ct_reg_discovery();
    ct_reg_ble();
    ct_reg_p2p();
    ct_reg_nat();
    ct_reg_bundle();
    ct_reg_pair();
    ct_reg_facade();
#ifndef CAIRN_NO_LIVE_PAIR
    ct_reg_pair_live();
#endif
    ct_reg_pair_logic();
    fprintf(stderr, "%d cases\n", g_count);

    for (i = 0; i < g_count; i++) {
        fprintf(stderr, "run %d %s\n", i, g_cases[i].name);
        g_hit = 0;
        g_cases[i].fn();
        if (g_hit) {
            g_fail++;
            fprintf(stderr, "FAIL %s\n", g_cases[i].name);
        } else {
            pass++;
        }
    }

    printf("\n%d passed, %d failed, %d total\n", pass, g_fail, g_count);
    return g_fail == 0 ? 0 : 1;
}
