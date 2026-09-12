/* Minimal RC4 stream cipher shared by payload generators and loaders
 * (stager unpacker, staged_loader resource packer). RC4 is symmetric: the same
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

/*
 * Allocate a fresh plaintext copy of an RC4-encrypted buffer, leaving the
 * ciphertext untouched. On success *plain points to a malloc'd buffer of
 * *plain_len bytes that the caller frees. Returns 0, or -1 for an empty
 * ciphertext, a NULL/oversized (>256 byte) key, or out-of-memory.
 */
int rc4_decrypt_alloc(const uint8_t *cipher, size_t cipher_len,
                      const uint8_t *key, size_t key_len, uint8_t **plain,
                      size_t *plain_len);

#endif /* COMMON_RC4_H */
