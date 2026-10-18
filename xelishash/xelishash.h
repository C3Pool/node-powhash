#ifndef XELISHASH_H
#define XELISHASH_H
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
#define XELISHASH_INPUT_LEN 112
#define XELISHASH_SCRATCH_WORDS (531 * 128)
/* xelis-hash v3 of a 112-byte MinerWork. scratch: XELISHASH_SCRATCH_WORDS u64s. */
void xelis_hash_v3(uint8_t in[XELISHASH_INPUT_LEN], uint8_t hash[32], uint64_t scratch[XELISHASH_SCRATCH_WORDS]);
/* BLAKE3-256 (a XELIS block hash is BLAKE3 of the same 112 bytes). */
void xelishash_blake3(const uint8_t *input, size_t len, uint8_t out32[32]);
#ifdef __cplusplus
}
#endif
#endif
