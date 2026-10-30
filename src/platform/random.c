/* Platform entropy.
 *
 * One file with two branches, for the same reason as platform.c: the build globs
 * src/**
/*.c.
 */
#include "cairn/crypto.h"

#ifdef _WIN32

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <bcrypt.h>

int cairn_random_bytes(void *buf, size_t len)
{
    if (buf == NULL) return CAIRN_ERR_ARG;
    if (len == 0) return CAIRN_OK;
    if (len > 0xffffffffu) return CAIRN_ERR_ARG;

    /* BCryptGenRandom is the supported call; RtlGenRandom is the old name for it and
     * is not declared in every SDK. */
    if (BCryptGenRandom(NULL, (PUCHAR)buf, (ULONG)len,
                        BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0)
        return CAIRN_ERR_IO;
    return CAIRN_OK;
}

#else /* POSIX: Linux, macOS, Android */

#define _DEFAULT_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

int cairn_random_bytes(void *buf, size_t len)
{
    uint8_t *p = (uint8_t *)buf;
    size_t got = 0;
    int fd;

    if (buf == NULL) return CAIRN_ERR_ARG;

    fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) return CAIRN_ERR_IO;
    while (got < len) {
        ssize_t n = read(fd, p + got, len - got);
        if (n <= 0) {
            if (n < 0 && errno == EINTR) continue;
            close(fd);
            return CAIRN_ERR_IO;
        }
        got += (size_t)n;
    }
    close(fd);
    return CAIRN_OK;
}

#endif
