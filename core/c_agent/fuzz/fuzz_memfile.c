#include "memfile.h"

#include "fuzz_common.h"

#include <stdlib.h>
#include <string.h>

/* The memfs read path inflates (and, with a password, decrypts) a stored blob.
 * Encryption is covered by fuzz_secureconn and PBKDF2 is a fixed KDF, so this
 * fuzzer uses no password: it exercises the container + gzip decode and a
 * transparent round-trip on arbitrary bytes without paying 100k PBKDF2 rounds
 * per input. */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  /* 1. Arbitrary bytes as a stored (unencrypted) entry. */
  c2_memfile_entry e;
  memset(&e, 0, sizeof(e));
  e.key = (char *)"memfs:///f";
  e.blob = (uint8_t *)data;
  e.blob_len = size;
  c2_memfile raw;
  memset(&raw, 0, sizeof(raw));
  raw.password = c2_str_of(NULL, 0);
  raw.entries = &e;
  raw.count = 1;
  raw.cap = 1;
  raw.max_bytes = C2_MEMFILE_DEFAULT_MAX_BYTES;
  uint8_t out[4096];
  size_t out_len = 0;
  (void)c2_memfile_read(&raw, c2_str_lit("memfs:///f"), out, sizeof(out),
                        &out_len);

  /* 2. Transparent write/read round-trip. */
  c2_memfile store;
  c2_memfile_init(&store, NULL, c2_str_of(NULL, 0), 8u * 1024u * 1024u);
  if (c2_memfile_write(&store, c2_str_lit("memfs:///k"), data, size) == C2_OK) {
    uint8_t *back = NULL;
    size_t back_len = 0;
    if (c2_memfile_read_alloc(&store, c2_str_lit("memfs:///k"), &back,
                              &back_len) == C2_OK) {
      if (back_len != size || (size && memcmp(back, data, size) != 0))
        c2_fuzz_fail("memfile round trip mismatch");
      free(back);
    }
  }
  c2_memfile_free(&store);
  return 0;
}
