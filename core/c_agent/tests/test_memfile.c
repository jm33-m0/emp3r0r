/*
 * test_memfile.c — transparent memfs read/write tests.
 *
 * The store must round-trip arbitrary bytes while holding only a
 * gzip-compressed, AES-GCM-encrypted blob in memory: the plaintext must not
 * appear in the stored bytes, a tampered blob must fail authentication, and the
 * byte budget must be enforced. The crypto backend is the system libcrypto
 * (linked directly), so this also exercises the same primitives the agent uses.
 */

#include "memfile.h"

#include "crypto.h"

#include "test.h"

#include <stdlib.h>
#include <string.h>

static void fill_pattern(uint8_t *p, size_t n) {
  for (size_t i = 0; i < n; i++)
    p[i] = (uint8_t)('a' + (i % 26)); /* highly compressible */
}

static int contains(const uint8_t *hay, size_t hlen, const char *needle) {
  size_t nlen = strlen(needle);
  if (nlen == 0 || hlen < nlen)
    return 0;
  for (size_t i = 0; i + nlen <= hlen; i++)
    if (memcmp(hay + i, needle, nlen) == 0)
      return 1;
  return 0;
}

static void test_roundtrip_with_encryption(c2_crypto_backend *be) {
  c2_memfile m;
  c2_memfile_init(&m, be, c2_str_lit("file-key-1"), 0);

  size_t n = 40000;
  uint8_t *data = malloc(n);
  fill_pattern(data, n);

  CHECK_EQ_LONG(c2_memfile_write(&m, c2_str_lit("memfs:///mod.bin"), data, n),
                0);
  CHECK(c2_memfile_has(&m, c2_str_lit("memfs:///mod.bin")));
  CHECK_EQ_LONG(c2_memfile_count(&m), 1);

  /* Compression is effective: the stored blob is far smaller than the input. */
  CHECK(c2_memfile_bytes(&m) < n);
  /* The blob is encrypted: the plaintext pattern is not present. */
  CHECK(!contains(m.entries[0].blob, m.entries[0].blob_len, "abcdefgh"));

  uint8_t *back = NULL;
  size_t back_len = 0;
  CHECK_EQ_LONG(c2_memfile_read_alloc(&m, c2_str_lit("memfs:///mod.bin"), &back,
                                      &back_len),
                0);
  CHECK_EQ_LONG(back_len, n);
  CHECK(back != NULL && memcmp(back, data, n) == 0);
  free(back);

  /* A tampered blob must fail GCM authentication, not return garbage. */
  m.entries[0].blob[m.entries[0].blob_len - 1] ^= 0x01;
  uint8_t out[64];
  size_t out_len = 0;
  CHECK(c2_memfile_read(&m, c2_str_lit("memfs:///mod.bin"), out, sizeof(out),
                        &out_len) != 0);

  CHECK_EQ_LONG(c2_memfile_remove(&m, c2_str_lit("memfs:///mod.bin")), 0);
  CHECK(!c2_memfile_has(&m, c2_str_lit("memfs:///mod.bin")));
  CHECK_EQ_LONG(c2_memfile_count(&m), 0);
  CHECK_EQ_LONG(c2_memfile_bytes(&m), 0);

  free(data);
  c2_memfile_free(&m);
}

static void test_roundtrip_without_encryption(c2_crypto_backend *be) {
  c2_memfile m;
  /* ptr == NULL disables encryption (compression still applies). */
  c2_memfile_init(&m, be, c2_str_of(NULL, 0), 0);
  const uint8_t msg[] = "plain-but-still-compressed";
  CHECK_EQ_LONG(c2_memfile_write(&m, c2_str_lit("memfs:///t"), msg,
                                 sizeof(msg) - 1),
                0);
  uint8_t *back = NULL;
  size_t back_len = 0;
  CHECK_EQ_LONG(c2_memfile_read_alloc(&m, c2_str_lit("memfs:///t"), &back,
                                      &back_len),
                0);
  CHECK_EQ_LONG(back_len, sizeof(msg) - 1);
  CHECK(back != NULL && memcmp(back, msg, sizeof(msg) - 1) == 0);
  free(back);
  c2_memfile_free(&m);
}

static void test_budget(c2_crypto_backend *be) {
  c2_memfile m;
  c2_memfile_init(&m, be, c2_str_lit("k"), 256); /* tiny budget */
  uint8_t data[4096];
  fill_pattern(data, sizeof(data));
  /* Incompressible random-ish data would exceed; compressible data may fit, so
   * assert the invariant instead: whatever is stored never exceeds the cap. */
  (void)c2_memfile_write(&m, c2_str_lit("memfs:///big"), data, sizeof(data));
  CHECK(c2_memfile_bytes(&m) <= 256);
  c2_memfile_free(&m);
}

static void test_key_normalization(void) {
  char key[64];
  size_t n = c2_memfile_key("/tmp/foo/bar.bin", strlen("/tmp/foo/bar.bin"), key,
                            sizeof(key));
  CHECK(n > 0 && strcmp(key, "memfs:///bar.bin") == 0);
  n = c2_memfile_key("memfs:///x", strlen("memfs:///x"), key, sizeof(key));
  CHECK(n > 0 && strcmp(key, "memfs:///x") == 0);
}

int main(void) {
  c2_crypto_backend *be = c2_crypto_open();
  if (be == NULL) {
    printf("%s: crypto backend unavailable, skipped\n", __FILE__);
    return 0;
  }
  test_roundtrip_with_encryption(be);
  test_roundtrip_without_encryption(be);
  test_budget(be);
  test_key_normalization();
  c2_crypto_close(be);
  TEST_DONE();
}
