#include "cairn/cairn.h"

const char *cairn_strerror(int status)
{
    switch (status) {
    case CAIRN_OK: return "ok";
    case CAIRN_ERR_ARG: return "bad argument";
    case CAIRN_ERR_MEMORY: return "out of memory";
    case CAIRN_ERR_UNIMPLEMENTED: return "unimplemented";
    case CAIRN_ERR_CRYPTO: return "crypto failure";
    case CAIRN_ERR_FORMAT: return "malformed input";
    case CAIRN_ERR_AUTH: return "authentication failed";
    case CAIRN_ERR_REPLAY: return "replayed message";
    case CAIRN_ERR_BUFFER: return "buffer too small";
    case CAIRN_ERR_TIMEOUT: return "timeout";
    case CAIRN_ERR_NOT_FOUND: return "not found";
    case CAIRN_ERR_STATE: return "wrong state";
    case CAIRN_ERR_IO: return "io error";
    case CAIRN_ERR_UNSUPPORTED: return "unsupported";
    default: return "unknown";
    }
}

void cairn_memzero(void *p, size_t n)
{
    volatile uint8_t *v = (volatile uint8_t *)p;
    while (n--) *v++ = 0;
}

int cairn_memeq(const void *a, const void *b, size_t n)
{
    const uint8_t *x = (const uint8_t *)a;
    const uint8_t *y = (const uint8_t *)b;
    uint8_t d = 0;
    size_t i;
    for (i = 0; i < n; i++) d |= (uint8_t)(x[i] ^ y[i]);
    return d == 0;
}