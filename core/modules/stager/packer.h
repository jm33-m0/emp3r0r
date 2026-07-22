#ifndef PACKER_H
#define PACKER_H
#include <stddef.h>
#include <stdint.h>

#ifndef CONFIG_XOR_KEY
#define CONFIG_XOR_KEY 0x5A
#endif



#ifndef STAGE1_SIZE
#define STAGE1_SIZE 0
#endif

#ifndef ENCODED_KEY
#define ENCODED_KEY 0x00
#endif

#define SEED_FD 3
#define EINTR 4
#define EAGAIN 11

void decode_config_string(char *dest, const unsigned char *encoded,
                          size_t max_len);
void derive_key_from_string(const char *str, uint8_t *key);
size_t decrypt_data(char *data, size_t data_size, const uint8_t *key,
                    const uint8_t *iv);
int build_payload_from_encrypted(char *enc_buf, size_t enc_size,
                                 const uint8_t *key, char **out_buf,
                                 size_t *out_size);
void xor_data(char *data, size_t len, const uint8_t *key, size_t key_len);
void get_random_safe(void *buf, size_t len);
void write_safe(int fd, const void *buf, size_t len);

#endif
