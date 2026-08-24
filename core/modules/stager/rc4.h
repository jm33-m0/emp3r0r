#ifndef RC4_H
#define RC4_H

#include <stddef.h>
#include <stdint.h>

/* Minimal RC4 stream cipher.
 * RC4 is symmetric: the same operation encrypts and decrypts.
 * It is used here in place of AES to keep the stager binary small. */

typedef struct {
  uint8_t s[256];
  uint8_t i;
  uint8_t j;
} rc4_ctx;

void rc4_init(rc4_ctx *ctx, const uint8_t *key, size_t key_len);
void rc4_crypt(rc4_ctx *ctx, uint8_t *data, size_t len);

#endif /* RC4_H */
