/* Bridges the PQClean randombytes interface to cairn's entropy source, so the
 * vendored KEM uses the same /dev/urandom path as everything else. The public
 * name comes from randombytes.h, which maps it to PQCLEAN_randombytes. */
#include "cairn/crypto.h"
#include "randombytes.h"

int PQCLEAN_randombytes(uint8_t *output, size_t n)
{
    if (output == NULL) return -1;
    return cairn_random_bytes(output, n) == CAIRN_OK ? 0 : -1;
}
