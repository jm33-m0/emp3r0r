/* Minimal RC4 stream cipher shared by payload generators and loaders
 * (stager unpacker, svc_loader resource packer). RC4 is symmetric: the same
 * operation encrypts and decrypts. It is used in place of AES to keep payload
 * binaries small. Keys are 1..256 bytes; empty keys are treated as a single
 * zero byte. RC4 here is obfuscation of data at rest, not a security
 * primitive.
 */

#ifndef COMMON_RC4_H
#define COMMON_RC4_H

#include <stddef.h>
#include <stdint.h>

typedef struct {
  uint8_t s[256];
  uint8_t i;
  uint8_t j;
} rc4_ctx;

/* KSA: prepare the state with key (1..256 bytes). Shorter keys are legal. */
void rc4_init(rc4_ctx *ctx, const uint8_t *key, size_t key_len);

/* PRGA: XOR len bytes of buf with the keystream, in place. */
void rc4_crypt(rc4_ctx *ctx, uint8_t *buf, size_t len);

#endif /* COMMON_RC4_H */
