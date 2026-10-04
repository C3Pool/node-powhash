#include "qpow_poseidon2.h"
#include "qpow_poseidon2_constants.h"

#include <cstring>

namespace qpow_poseidon2 {
namespace {

constexpr uint64_t P = 0xFFFFFFFF00000001ULL;
constexpr size_t RATE = 8;
constexpr size_t OUTPUT = 4;
constexpr size_t HALF_EXTERNAL_ROUNDS = 4;
constexpr size_t INTERNAL_ROUNDS = 22;

// Every value below stays canonical (< p). Upstream keeps non-canonical
// representatives internally, which only changes representation, not the field
// element; outputs are canonicalised there before serialisation, so they match.
inline uint64_t add(uint64_t a, uint64_t b) {
    const uint64_t s = a + b;
    // a, b < p < 2^64, so a + b < 2p; subtract p when the sum wrapped or reached p.
    return (s < a || s >= P) ? s - P : s;
}

inline uint64_t mul(uint64_t a, uint64_t b) {
    return static_cast<uint64_t>((static_cast<unsigned __int128>(a) * b) % P);
}

inline uint64_t exp7(uint64_t x) {
    const uint64_t x2 = mul(x, x);
    const uint64_t x3 = mul(x2, x);
    const uint64_t x4 = mul(x2, x2);
    return mul(x3, x4);
}

inline uint64_t reduce(uint64_t x) { return x >= P ? x - P : x; }

void apply_mat4(uint64_t* x) {
    const uint64_t t01 = add(x[0], x[1]);
    const uint64_t t23 = add(x[2], x[3]);
    const uint64_t t0123 = add(t01, t23);
    const uint64_t t01123 = add(t0123, x[1]);
    const uint64_t t01233 = add(t0123, x[3]);
    const uint64_t x0 = x[0];
    const uint64_t x2 = x[2];
    x[3] = add(t01233, add(x0, x0));  // 3*x0 + x1 + x2 + 2*x3
    x[1] = add(t01123, add(x2, x2));  // x0 + 2*x1 + 3*x2 + x3
    x[0] = add(t01123, t01);          // 2*x0 + 3*x1 + x2 + x3
    x[2] = add(t01233, t23);          // x0 + x1 + 2*x2 + 3*x3
}

void external_linear_layer(uint64_t state[WIDTH]) {
    for (size_t c = 0; c < WIDTH; c += 4) apply_mat4(state + c);
    uint64_t sums[4] = {0, 0, 0, 0};
    for (size_t k = 0; k < 4; ++k) {
        for (size_t j = 0; j < WIDTH; j += 4) sums[k] = add(sums[k], state[j + k]);
    }
    for (size_t i = 0; i < WIDTH; ++i) state[i] = add(state[i], sums[i % 4]);
}

void internal_linear_layer(uint64_t state[WIDTH]) {
    uint64_t sum = 0;
    for (size_t i = 0; i < WIDTH; ++i) sum = add(sum, state[i]);
    for (size_t i = 0; i < WIDTH; ++i) state[i] = add(sum, mul(state[i], MATRIX_DIAG[i]));
}

void external_round(uint64_t state[WIDTH], const uint64_t rc[WIDTH]) {
    for (size_t i = 0; i < WIDTH; ++i) state[i] = exp7(add(state[i], rc[i]));
    external_linear_layer(state);
}

struct Sponge {
    uint64_t state[WIDTH] = {0};
    uint64_t buf[RATE] = {0};
    size_t buf_len = 0;

    void push(uint64_t felt) {
        buf[buf_len++] = felt;
        if (buf_len == RATE) {
            for (size_t i = 0; i < RATE; ++i) state[i] = add(state[i], buf[i]);
            permute(state);
            std::memset(buf, 0, sizeof(buf));
            buf_len = 0;
        }
    }

    // serialization::bytes_to_felts_iter: 4 little-endian bytes per element, then one
    // terminator element carrying any partial tail followed by a 0x01 byte.
    void append_bytes(const uint8_t* data, size_t length) {
        size_t pos = 0;
        for (; pos + 4 <= length; pos += 4) {
            push(static_cast<uint64_t>(data[pos]) | static_cast<uint64_t>(data[pos + 1]) << 8 |
                 static_cast<uint64_t>(data[pos + 2]) << 16 | static_cast<uint64_t>(data[pos + 3]) << 24);
        }
        uint8_t last[4] = {0, 0, 0, 0};
        const size_t rest = length - pos;
        std::memcpy(last, data + pos, rest);
        last[rest] = 1;
        push(static_cast<uint64_t>(last[0]) | static_cast<uint64_t>(last[1]) << 8 |
             static_cast<uint64_t>(last[2]) << 16 | static_cast<uint64_t>(last[3]) << 24);
    }

    // finalize_state: push ONE, then ZERO until the block is absorbed.
    void finalize() {
        push(1);
        while (buf_len != 0) push(0);
    }

    // serialization::digest_to_bytes: the first four elements, canonical u64 little-endian.
    void digest(uint8_t out[32]) const {
        for (size_t i = 0; i < OUTPUT; ++i) {
            const uint64_t v = reduce(state[i]);
            for (size_t b = 0; b < 8; ++b) out[i * 8 + b] = static_cast<uint8_t>(v >> (8 * b));
        }
    }
};

}  // namespace

void permute(uint64_t state[WIDTH]) {
    external_linear_layer(state);
    for (size_t r = 0; r < HALF_EXTERNAL_ROUNDS; ++r) external_round(state, INITIAL_EXTERNAL_CONSTANTS[r]);
    for (size_t r = 0; r < INTERNAL_ROUNDS; ++r) {
        state[0] = exp7(add(state[0], INTERNAL_CONSTANTS[r]));
        internal_linear_layer(state);
    }
    for (size_t r = 0; r < HALF_EXTERNAL_ROUNDS; ++r) external_round(state, TERMINAL_EXTERNAL_CONSTANTS[r]);
}

void hash_squeeze_twice(const uint8_t* input, size_t length, uint8_t out[64]) {
    Sponge sponge;
    sponge.append_bytes(input, length);
    sponge.finalize();
    sponge.digest(out);
    permute(sponge.state);
    sponge.digest(out + 32);
}

void nonce_hash(const uint8_t mining_hash[32], const uint8_t nonce[64], uint8_t out[64]) {
    uint8_t input[96];
    std::memcpy(input, mining_hash, 32);
    std::memcpy(input + 32, nonce, 64);
    hash_squeeze_twice(input, sizeof(input), out);
}

}  // namespace qpow_poseidon2
