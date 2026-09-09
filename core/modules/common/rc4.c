#include "rc4.h"

static void rc4_swap(uint8_t *a, uint8_t *b) {
  uint8_t t = *a;
  *a = *b;
  *b = t;
}

void rc4_init(rc4_ctx *ctx, const uint8_t *key, size_t key_len) {
  static const uint8_t zero_key = 0;
  size_t i;
  uint8_t j = 0;

  /* RC4 keys are 1..256 bytes. Guard against NULL/empty keys (which would
   * divide by zero below) by treating them as a single zero byte. */
  if (key == NULL || key_len == 0) {
    key = &zero_key;
    key_len = 1;
  }

  for (i = 0; i < 256; i++)
    ctx->s[i] = (uint8_t)i;

  for (i = 0; i < 256; i++) {
    j = (uint8_t)(j + ctx->s[i] + key[i % key_len]);
    rc4_swap(&ctx->s[i], &ctx->s[j]);
  }

  ctx->i = 0;
  ctx->j = 0;
}

void rc4_crypt(rc4_ctx *ctx, uint8_t *data, size_t len) {
  uint8_t i = ctx->i;
  uint8_t j = ctx->j;
  size_t n;

  for (n = 0; n < len; n++) {
    i = (uint8_t)(i + 1);
    j = (uint8_t)(j + ctx->s[i]);
    rc4_swap(&ctx->s[i], &ctx->s[j]);
    data[n] ^= ctx->s[(uint8_t)(ctx->s[i] + ctx->s[j])];
  }

  ctx->i = i;
  ctx->j = j;
}
