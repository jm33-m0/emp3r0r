#ifndef PACKER_H
#define PACKER_H

#include <stddef.h>
#include <stdint.h>

#ifndef CONFIG_XOR_KEY
#define CONFIG_XOR_KEY 0x5A
#endif

/* Length of the RC4 key derived from the download key string.
 * Must stay in sync with derivedKeyLen in core/lib/listener/staged_blob.go. */
#define DERIVED_KEY_LEN 16

/* Decode a config string that was XOR-encoded at build time (see Makefile). */
void decode_config_string(char *dest, const unsigned char *encoded,
                          size_t max_len);

/* Derive a fixed-size RC4 key from the passphrase. Mirrors
 * deriveKeyFromString() in core/lib/listener/staged_blob.go; keep in sync. */
void derive_key_from_string(const char *str, uint8_t *key);

#endif
