#include "packer.h"
#include "aes.h"
#include "tinf.h"
#include "utils.h"

int build_payload_from_encrypted(char *enc_buf, size_t enc_size,
                                 const uint8_t *key, char **out_buf,
                                 size_t *out_size) {
  if (!enc_buf || enc_size <= 16 || !out_buf || !out_size)
    return -1;

  uint8_t iv[16];
  memcpy(iv, enc_buf, 16);
  size_t encrypted_body = enc_size - 16;
  char *cipher = enc_buf + 16;

  decrypt_data(cipher, encrypted_body, key, iv);

  unsigned int capacity = (unsigned int)encrypted_body * 10;
  char *decomp = NULL;
  int res = TINF_OK;
  unsigned int out_len = 0;

  for (int attempt = 0; attempt < 3; attempt++) {
    decomp = calloc(capacity, sizeof(char));
    if (!decomp)
      return -1;
    out_len = capacity;
    res = tinf_uncompress(decomp, &out_len, cipher, encrypted_body);
    if (res == TINF_OK)
      break;
    free(decomp);
    decomp = NULL;
    capacity *= 2;
  }

  if (res != TINF_OK || !decomp)
    return -1;

  *out_buf = decomp;
  *out_size = out_len;
  return 0;
}

size_t decrypt_data(char *data, size_t data_size, const uint8_t *key,
                    const uint8_t *iv) {
  struct AES_ctx ctx;
  AES_init_ctx_iv(&ctx, key, iv);
  AES_CTR_xcrypt_buffer(&ctx, (uint8_t *)data, data_size);
  return data_size;
}

void xor_data(char *data, size_t len, const uint8_t *key, size_t key_len) {
  for (size_t i = 0; i < len; i++) {
    data[i] ^= key[i % key_len];
  }
}

void get_random_safe(void *buf, size_t len) {
  size_t total = 0;
  char *p = (char *)buf;
  while (total < len) {
    long ret = getrandom(p + total, len - total, 0);
    if (ret < 0) {
      if (ret == -EINTR || ret == -EAGAIN)
        continue;
      break;
    }
    if (ret == 0)
      break;
    total += (size_t)ret;
  }
}

void write_safe(int fd, const void *buf, size_t len) {
  size_t total = 0;
  const char *p = (const char *)buf;
  while (total < len) {
    long ret = write(fd, p + total, len - total);
    if (ret < 0) {
      if (ret == -EINTR || ret == -EAGAIN)
        continue;
      break;
    }
    if (ret == 0)
      continue;
    total += (size_t)ret;
  }
}

void decode_config_string(char *dest, const unsigned char *encoded,
                          size_t max_len) {
  size_t i = 0;
  while (i < max_len - 1) {
    if (encoded[i] == 0x00)
      break;
    dest[i] = encoded[i] ^ CONFIG_XOR_KEY;
    i++;
  }
  dest[i] = '\0';
}

void derive_key_from_string(const char *str, uint8_t *key) {
  uint32_t temp_key[4] = {0};
  size_t len = strlen(str);
  for (int i = 0; i < 4; i++) {
    for (size_t j = 0; j < len / 4; j++) {
      temp_key[i] ^= ((uint32_t)str[i + j * 4]) << (j % 4 * 8);
    }
  }
  memcpy(key, temp_key, 16);
}
