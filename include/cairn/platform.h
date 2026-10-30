/* cairn: platform abstraction.
 *
 * Only three things differ enough between targets to need this: the clock, a way
 * to wait, and entropy. Everything else in the library is plain C. Keeping the
 * surface this small is what makes the Android, Linux, Windows and macOS builds
 * the same protocol code with a thin shim each.
 */
#ifndef CAIRN_PLATFORM_H
#define CAIRN_PLATFORM_H

#include <stddef.h>
#include <stdint.h>

#include "cairn/cairn.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Monotonic milliseconds. Must not jump when the wall clock is adjusted, because
 * the ratchet and the NAT timers both compare these values. */
uint64_t cairn_time_ms(void);

/* Sleeps for at least ms milliseconds. */
void cairn_sleep_ms(uint32_t ms);

/* Local host name, truncated to outcap and NUL terminated. Used as the default
 * display name in a beacon. */
int cairn_host_name(char *out, size_t outcap);

#ifdef __cplusplus
}
#endif

#endif /* CAIRN_PLATFORM_H */