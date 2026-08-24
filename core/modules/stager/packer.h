#ifndef PACKER_H
#define PACKER_H

#include <stddef.h>
#include <stdint.h>

#ifndef CONFIG_XOR_KEY
#define CONFIG_XOR_KEY 0x5A
#endif

void decode_config_string(char *dest, const unsigned char *encoded,
                          size_t max_len);
void derive_key_from_string(const char *str, uint8_t *key);

#endif
