/* Platform shims: clock, sleep, host name.
 *
 * One file with two branches rather than two files, because the build globs
 * src/**
/*.c and two files would define the same symbols on both platforms.
 */
#include "cairn/platform.h"

#ifdef _WIN32
#  define WIN32_LEAN_AND_MEAN
#  include <windows.h>
#  include <string.h>

uint64_t cairn_time_ms(void)
{
    LARGE_INTEGER freq, now;

    if (!QueryPerformanceFrequency(&freq) || freq.QuadPart == 0) return 0;
    if (!QueryPerformanceCounter(&now)) return 0;
    /* Microseconds first, then down to milliseconds, to keep the division exact for
     * the durations a phone or laptop cares about. */
    return (uint64_t)((now.QuadPart * 1000) / freq.QuadPart);
}

void cairn_sleep_ms(uint32_t ms)
{
    Sleep((DWORD)ms);
}

int cairn_host_name(char *out, size_t outcap)
{
    DWORD cap;

    if (out == NULL || outcap == 0) return CAIRN_ERR_ARG;
    if (outcap > 0xffffffffu) return CAIRN_ERR_ARG;

    cap = (DWORD)outcap;
    if (!GetComputerNameA(out, &cap)) {
        out[0] = '\0';
        return CAIRN_ERR_IO;
    }
    out[outcap - 1] = '\0';
    if (out[0] == '\0') memcpy(out, "cairn", 6);
    return CAIRN_OK;
}

#else /* POSIX: Linux, macOS, Android */

#define _POSIX_C_SOURCE 200809L

#include <string.h>
#include <time.h>
#include <unistd.h>

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
    /* A signal can cut the sleep short; the contract only says "at least". */
    while (nanosleep(&ts, &ts) != 0) {
        if (ts.tv_sec == 0 && ts.tv_nsec == 0) break;
    }
}

int cairn_host_name(char *out, size_t outcap)
{
    if (out == NULL || outcap == 0) return CAIRN_ERR_ARG;
    if (gethostname(out, outcap) != 0) {
        out[0] = '\0';
        return CAIRN_ERR_IO;
    }
    /* gethostname does not promise a terminator when the name is too long. */
    out[outcap - 1] = '\0';
    if (out[0] == '\0') memcpy(out, "cairn", 6);
    return CAIRN_OK;
}

#endif
