#include "BLAKE3/c/blake3.h"
#include "xelishash.h"

void xelishash_blake3(const uint8_t *input, size_t len, uint8_t out32[32]) {
    blake3_hasher hasher;
    blake3_hasher_init(&hasher);
    blake3_hasher_update(&hasher, input, len);
    blake3_hasher_finalize(&hasher, out32, BLAKE3_OUT_LEN);
}
