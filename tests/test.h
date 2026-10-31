#ifndef CAIRN_TEST_H
#define CAIRN_TEST_H

#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef void (*ct_fn)(void);

void ct_register(const char *name, ct_fn fn);
void ct_failf(const char *file, int line, const char *fmt, ...);

/* Marks the current case as not applicable here instead of failed. Used when the
 * case needs something the environment cannot provide, such as UDP loopback between
 * two sockets; pretending it passed would be worse than saying so. */
void ct_skip(const char *reason);

#define CT_TEST(fn) static void fn(void)
#define CT_REG(fn) ct_register(#fn, fn)

#define CT_SKIP(reason)                                                       \
    do {                                                                      \
        ct_skip(reason);                                                      \
        return;                                                               \
    } while (0)

#define CT_ASSERT(cond)                                                       \
    do {                                                                      \
        if (!(cond)) ct_failf(__FILE__, __LINE__, "%s", #cond);                \
    } while (0)

#define CT_ASSERT_EQ_INT(actual, expected)                                    \
    do {                                                                      \
        long long ct_a = (long long)(actual);                                  \
        long long ct_e = (long long)(expected);                                \
        if (ct_a != ct_e)                                                      \
            ct_failf(__FILE__, __LINE__, "%s = %lld, want %lld",                \
                     #actual, ct_a, ct_e);                                    \
    } while (0)

#define CT_ASSERT_MEM_EQ(actual, expected, len)                               \
    do {                                                                      \
        if (memcmp((actual), (expected), (size_t)(len)) != 0)                   \
            ct_failf(__FILE__, __LINE__, "bytes differ: %s vs %s",              \
                     #actual, #expected);                                     \
    } while (0)

#endif
