#ifndef NEXAPOW_H
#define NEXAPOW_H
#include <stddef.h>
#ifdef __cplusplus
extern "C" {
#endif
/* Largest nonce the Nexa node accepts (MAX_NONCE_SIZE). */
#define NEXAPOW_MAX_NONCE 16
int nexapow_init(void);
/* commitment32: header commitment in raw (internal) byte order. out32: SHA256 of
 * the Schnorr signature, to be read as a little-endian integer. Returns 0 for an
 * invalid solution (mining hash not a valid secret key) or bad arguments. */
int nexapow_hash(const unsigned char *commitment32, const unsigned char *nonce, size_t nonce_len, unsigned char *out32);
#ifdef __cplusplus
}
#endif
#endif
