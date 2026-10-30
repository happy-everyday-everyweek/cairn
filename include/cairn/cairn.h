/* cairn: minimal cross-platform peer discovery and encrypted transfer. */
#ifndef CAIRN_H
#define CAIRN_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define CAIRN_VERSION_MAJOR 0
#define CAIRN_VERSION_MINOR 1

enum cairn_status {
    CAIRN_OK = 0,
    CAIRN_ERR_ARG = -1,
    CAIRN_ERR_MEMORY = -2,
    CAIRN_ERR_UNIMPLEMENTED = -3,
    CAIRN_ERR_CRYPTO = -4,
    CAIRN_ERR_FORMAT = -5,
    CAIRN_ERR_AUTH = -6,
    CAIRN_ERR_REPLAY = -7,
    CAIRN_ERR_BUFFER = -8,
    CAIRN_ERR_TIMEOUT = -9,
    CAIRN_ERR_NOT_FOUND = -10,
    CAIRN_ERR_STATE = -11,
    CAIRN_ERR_IO = -12,
    CAIRN_ERR_UNSUPPORTED = -13
};

const char *cairn_status_string(int status);

/* Zeroes memory without the compiler eliding the store. */
void cairn_memzero(void *p, size_t n);

/* Constant time equality: 1 when equal, 0 otherwise. */
int cairn_memeq(const void *a, const void *b, size_t n);

#ifdef __cplusplus
}
#endif

#endif /* CAIRN_H */