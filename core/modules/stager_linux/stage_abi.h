#ifndef STAGER_STAGE_ABI_H
#define STAGER_STAGE_ABI_H

#include <stddef.h>
#include <stdint.h>

#include "util/packer.h"

/*
 * ABI between the stager stub and the payload provider.
 *
 * The provider fills this with the agent PIC still RC4-encrypted (read/write)
 * plus the key to decrypt it. It may be the downloader stage (a separate PIC
 * blob) or the local embedding path (a prebuilt C agent PIC copied out of the
 * stager image).
 *
 * Decryption is deliberately deferred to whoever runs the PIC. With SUPERVISE
 * the parent keeps only ciphertext RW: each sacrificial child decrypts the
 * shared pages into its own RX view (copy-on-write), runs, and tears it down
 * on exit. Without SUPERVISE the single stub process decrypts in place and
 * flips to RX just before entering the payload.
 */
struct stager_payload {
  char *data;   /* agent PIC, still RC4-encrypted (RW mmap) */
  size_t size;  /* number of valid bytes in data */
  uint8_t key[DERIVED_KEY_LEN]; /* RC4 key for data */
};

#endif /* STAGER_STAGE_ABI_H */
