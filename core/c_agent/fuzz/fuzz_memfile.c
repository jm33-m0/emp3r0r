#include "memfile.h"

#include "fuzz_common.h"
#include "stub_crypto.h"

#include <stdlib.h>
#include <string.h>

/* The memfs container combines gzip with optional password-based AES-GCM. The
 * unencrypted half only needs gzip; the encrypted half uses the deterministic
 * stub KDF/AEAD so it runs at fuzzing speed instead of paying 100k PBKDF2
 * rounds per input. Both halves cover a transparent write/read round-trip and
 * the hostile-blob read path. */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  uint32_t rng = 0x13579bdfu ^ (uint32_t)size;
  c2_crypto_backend be;
  stub_crypto_init(&be, &rng);

  uint8_t out[4096];
  size_t out_len = 0;

  /* 1. Arbitrary bytes as a stored unencrypted entry. */
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
  (void)c2_memfile_read(&raw, c2_str_lit("memfs:///f"), out, sizeof(out),
                        &out_len);

  /* 2. Unencrypted transparent round-trip. */
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

  /* 3. Encrypted transparent round-trip. */
  c2_str password = c2_str_lit("fuzz-memfile-password");
  c2_memfile enc_store;
  c2_memfile_init(&enc_store, &be, password, 8u * 1024u * 1024u);
  if (c2_memfile_write(&enc_store, c2_str_lit("memfs:///e"), data, size) ==
      C2_OK) {
    uint8_t *back = NULL;
    size_t back_len = 0;
    if (c2_memfile_read_alloc(&enc_store, c2_str_lit("memfs:///e"), &back,
                              &back_len) == C2_OK) {
      if (back_len != size || (size && memcmp(back, data, size) != 0))
        c2_fuzz_fail("encrypted memfile round trip mismatch");
      free(back);
    }
  }
  c2_memfile_free(&enc_store);

  /* 4. Arbitrary bytes as an encrypted stored entry: container bounds,
   * authentication failure, and the post-decrypt gzip path. */
  c2_memfile_entry e2;
  memset(&e2, 0, sizeof(e2));
  e2.key = (char *)"memfs:///g";
  e2.blob = (uint8_t *)data;
  e2.blob_len = size;
  c2_memfile raw_enc;
  memset(&raw_enc, 0, sizeof(raw_enc));
  raw_enc.be = &be;
  raw_enc.password = password;
  raw_enc.entries = &e2;
  raw_enc.count = 1;
  raw_enc.cap = 1;
  raw_enc.max_bytes = C2_MEMFILE_DEFAULT_MAX_BYTES;
  (void)c2_memfile_read(&raw_enc, c2_str_lit("memfs:///g"), out, sizeof(out),
                        &out_len);

  /* 5. Key normalization: arbitrary path-like bytes into a fixed buffer. */
  char key[64] = {0};
  size_t key_len = c2_memfile_key((const char *)data, size, key, sizeof(key));
  if (key_len >= sizeof(key) || (key_len > 0 && key[key_len] != '\0'))
    c2_fuzz_fail("memfile key was not NUL-terminated within its buffer");
  char tiny[9];
  size_t tiny_cap = 1 + (size ? size % sizeof(tiny) : 0);
  size_t tiny_len = c2_memfile_key((const char *)data, size, tiny, tiny_cap);
  if (tiny_len >= tiny_cap)
    c2_fuzz_fail("memfile key exceeded the destination capacity");

  return 0;
}
