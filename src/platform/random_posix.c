/* Platform entropy, POSIX side. */
#define _DEFAULT_SOURCE
#include "cairn/crypto.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
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