/*
 * test_c2_bof.c — Linux BOF execution through the coffloader_linux loader.
 *
 * The Makefile builds the real loader (`coffloader_linux.so`) and the real
 * `hello_linux` BOF at test time and passes their paths in, so this exercises
 * exactly the runtime path: memfd + dlopen + bof_run + argument packing.
 */

#include "c2_bof.h"

#include "test.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef BOF_LOADER_PATH
#define BOF_LOADER_PATH ""
#endif
#ifndef BOF_OBJ_PATH
#define BOF_OBJ_PATH ""
#endif

static uint8_t *slurp(const char *path, size_t *len) {
  FILE *f = fopen(path, "rb");
  if (f == NULL)
    return NULL;
  if (fseek(f, 0, SEEK_END) != 0) {
    fclose(f);
    return NULL;
  }
  long n = ftell(f);
  if (n < 0 || fseek(f, 0, SEEK_SET) != 0) {
    fclose(f);
    return NULL;
  }
  uint8_t *b = (uint8_t *)malloc(n > 0 ? (size_t)n : 1);
  if (b == NULL) {
    fclose(f);
    return NULL;
  }
  if (n > 0 && fread(b, 1, (size_t)n, f) != (size_t)n) {
    fclose(f);
    free(b);
    return NULL;
  }
  fclose(f);
  *len = (size_t)n;
  return b;
}

static void test_pack_args(void) {
  uint8_t out[128];
  size_t n = 0;

  /* z<str>: uint32 body || uint32 len+1 || bytes || NUL */
  c2_str z[1] = {c2_str_lit("zWorld")};
  CHECK_EQ_LONG(c2_bof_pack_args(z, 1, out, sizeof(out), &n), C2_OK);
  CHECK_EQ_LONG(n, 4 + 4 + 5 + 1);
  CHECK_EQ_LONG(out[4], 6); /* inner length includes the terminator (LE) */

  /* i<int>: 4-byte LE */
  c2_str i[1] = {c2_str_lit("i-2")};
  CHECK_EQ_LONG(c2_bof_pack_args(i, 1, out, sizeof(out), &n), C2_OK);
  CHECK_EQ_LONG(n, 4 + 4);

  /* s<short>: 2-byte LE */
  c2_str s[1] = {c2_str_lit("s258")};
  CHECK_EQ_LONG(c2_bof_pack_args(s, 1, out, sizeof(out), &n), C2_OK);
  CHECK_EQ_LONG(n, 4 + 2);

  /* b<hex>: length + raw bytes */
  c2_str b[1] = {c2_str_lit("b00ff00")};
  CHECK_EQ_LONG(c2_bof_pack_args(b, 1, out, sizeof(out), &n), C2_OK);
  CHECK_EQ_LONG(n, 4 + 4 + 3);

  /* Z<wide>: UTF-16LE, 2 bytes per ASCII char, plus a 2-byte terminator */
  c2_str w[1] = {c2_str_lit("ZAb")};
  CHECK_EQ_LONG(c2_bof_pack_args(w, 1, out, sizeof(out), &n), C2_OK);
  CHECK_EQ_LONG(n, 4 + 4 + 4 + 2);

  /* Malformed tokens are rejected, not mis-packed. */
  c2_str bad[1] = {c2_str_lit("qoops")};
  CHECK(c2_bof_pack_args(bad, 1, out, sizeof(out), &n) != C2_OK);

  /* Too small a buffer is refused. */
  uint8_t tiny[4];
  CHECK(c2_bof_pack_args(z, 1, tiny, sizeof(tiny), &n) != C2_OK);
}

int main(void) {
  test_pack_args();

  if (BOF_LOADER_PATH[0] == '\0' || BOF_OBJ_PATH[0] == '\0') {
    printf("%s: loader/object not provided, skipped runtime part\n", __FILE__);
    TEST_DONE();
    return 0;
  }

  size_t loader_len = 0;
  size_t bof_len = 0;
  uint8_t *loader = slurp(BOF_LOADER_PATH, &loader_len);
  uint8_t *bof = slurp(BOF_OBJ_PATH, &bof_len);
  CHECK(loader != NULL && loader_len > 0);
  CHECK(bof != NULL && bof_len > 0);
  if (loader == NULL || bof == NULL) {
    free(loader);
    free(bof);
    TEST_DONE();
    return 0;
  }

  c2_str args[1] = {c2_str_lit("zWorld")};
  uint8_t packed[64];
  size_t packed_len = 0;
  CHECK_EQ_LONG(c2_bof_pack_args(args, 1, packed, sizeof(packed), &packed_len),
                C2_OK);

  char *out = NULL;
  CHECK_EQ_LONG(c2_bof_run(loader, loader_len, bof, bof_len, "go", packed,
                           packed_len, &out),
                C2_OK);
  CHECK(out != NULL && strstr(out, "Hello World!") != NULL);
  free(out);

  /* An unknown export must fail cleanly, not crash or leak an output. On
   * failure *out carries the loader's error message, if any. */
  out = NULL;
  CHECK(c2_bof_run(loader, loader_len, bof, bof_len, "does_not_exist", packed,
                   packed_len, &out) != C2_OK);
  if (out != NULL) {
    CHECK(strstr(out, "not found") != NULL);
    free(out);
  }

  free(loader);
  free(bof);
  TEST_DONE();
}
