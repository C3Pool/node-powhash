#ifndef NODE_POWHASH_QPOW_POSEIDON2_H
#define NODE_POWHASH_QPOW_POSEIDON2_H

// Quantus (QTC) QPoW: Poseidon2 over the Goldilocks field, ported from
// Quantus-Network/qp-poseidon (qp-poseidon-core 3.1.0) and qpow-math.

#include <cstddef>
#include <cstdint>

namespace qpow_poseidon2 {

constexpr size_t WIDTH = 12;

// The raw Poseidon2 permutation; state elements must be canonical (< p).
void permute(uint64_t state[WIDTH]);

// qp_poseidon_core::hash_squeeze_twice: absorb `length` bytes, return 64 bytes.
void hash_squeeze_twice(const uint8_t* input, size_t length, uint8_t out[64]);

// qpow_math::get_nonce_hash: hash_squeeze_twice(mining_hash || nonce). The 64-byte
// result is read big-endian as a U512 and is valid when < U512::MAX / difficulty.
void nonce_hash(const uint8_t mining_hash[32], const uint8_t nonce[64], uint8_t out[64]);

}  // namespace qpow_poseidon2

#endif
