#include "packer.h"
#include "utils.h"

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
