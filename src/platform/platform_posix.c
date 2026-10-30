/* Platform shims: POSIX (Linux, macOS, Android) side. */
#define _DEFAULT_SOURCE
#define _POSIX_C_SOURCE 200809L

#include "cairn/platform.h"

#include <time.h>
#include <unistd.h>
#include <string.h>

uint64_t cairn_time_ms(void)
{
    struct timespec ts;

    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) return 0;
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)(ts.tv_nsec / 1000000);
}

void cairn_sleep_ms(uint32_t ms)
{
    struct timespec ts;

    ts.tv_sec = (time_t)(ms / 1000u);
    ts.tv_nsec = (long)(ms % 1000u) * 1000000L;
    /* A signal can cut the sleep short; the contract only says "at least", so
     * resuming the remainder is the correct behaviour. */
    while (nanosleep(&ts, &ts) != 0) {
        if (ts.tv_sec == 0 && ts.tv_nsec == 0) break;
    }
}

int cairn_host_name(char *out, size_t outcap)
{
    size_t n;

    if (out == NULL || outcap == 0) return CAIRN_ERR_ARG;
    if (gethostname(out, outcap) != 0) {
        out[0] = '\0';
        return CAIRN_ERR_IO;
    }
    /* gethostname does not promise a terminator when the name is too long. */
    out[outcap - 1] = '\0';
    n = strlen(out);
    if (n == 0) {
        memcpy(out, "cairn", 6);
    }
    return CAIRN_OK;
}