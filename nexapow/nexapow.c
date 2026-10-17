/* NexaPow (Nexa mainnet PoW, powAlgorithm 1) on Bitcoin Cash style Schnorr.
 * Built as one translation unit over the secp256k1 copy vendored from the Nexa
 * node (gitlab.com/nexa/nexa @122fc540, src/secp256k1), which carries the BCH
 * schnorr module: RFC6979 nonces tagged "Schnorr+SHA256  ", R.y a quadratic
 * residue, e = SHA256(R.x || compressed P || msg). Nexa node src/pow.cpp:
 *   mining = SHA256d(commitment || compactsize(len) || nonce)
 *   h1     = SHA256(mining)              (no previous-block mixing before HF2)
 *   sig    = SchnorrSign(key = mining, msg = h1)
 *   pow    = SHA256(sig)                 compared little-endian against target */
#define USE_NUM_NONE 1
#define USE_FIELD_INV_BUILTIN 1
#define USE_SCALAR_INV_BUILTIN 1
#if defined(__SIZEOF_INT128__)
#define HAVE___INT128 1
#define USE_FIELD_5X52 1
#define USE_SCALAR_4X64 1
#else
#define USE_FIELD_10X26 1
#define USE_SCALAR_8X32 1
#endif
#define ECMULT_WINDOW_SIZE 15
#define ECMULT_GEN_PREC_BITS 4
#define ENABLE_MODULE_SCHNORR 1
#include "secp256k1/src/secp256k1.c"
#include "nexapow.h"

static secp256k1_context *nexapow_ctx = NULL;

int nexapow_init(void) {
    if (nexapow_ctx == NULL) nexapow_ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
    return nexapow_ctx != NULL;
}

static void nexapow_sha256(const unsigned char *a, size_t alen, const unsigned char *b, size_t blen, unsigned char *out32) {
    secp256k1_sha256 hash;
    secp256k1_sha256_initialize(&hash);
    secp256k1_sha256_write(&hash, a, alen);
    if (blen) secp256k1_sha256_write(&hash, b, blen);
    secp256k1_sha256_finalize(&hash, out32);
}

int nexapow_hash(const unsigned char *commitment32, const unsigned char *nonce, size_t nonce_len, unsigned char *out32) {
    unsigned char prefix[33], inner[32], mining[32], h1[32], sig[64];
    if (nexapow_ctx == NULL || nonce_len == 0 || nonce_len > NEXAPOW_MAX_NONCE) return 0;
    memcpy(prefix, commitment32, 32);
    prefix[32] = (unsigned char)nonce_len;
    nexapow_sha256(prefix, sizeof(prefix), nonce, nonce_len, inner);
    nexapow_sha256(inner, 32, NULL, 0, mining);
    nexapow_sha256(mining, 32, NULL, 0, h1);
    /* The mining hash is the secret key; zero or >= n is an invalid solution (CKey::IsValid). */
    if (!secp256k1_ec_seckey_verify(nexapow_ctx, mining)) return 0;
    if (!secp256k1_schnorr_sign(nexapow_ctx, sig, h1, mining, secp256k1_nonce_function_rfc6979, NULL)) return 0;
    nexapow_sha256(sig, sizeof(sig), NULL, 0, out32);
    return 1;
}
