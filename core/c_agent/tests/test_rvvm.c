/*
 * test_rvvm.c — RV32 BOF execution through the rvvm module.
 *
 * The Makefile builds the real interpreter and RV32 ET_REL BOF fixtures with
 * the shipped zig, and passes their paths in, so this exercises the runtime
 * path: in-memory mapping of the interpreter, runtime/BOF relocation, symbol
 * resolution against the embedded Beacon/libc runtime, and the host calls.
 */

#include "test.h"

#include "util/elfload.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef RVVM_MODULE_PATH
#define RVVM_MODULE_PATH ""
#endif
#ifndef RVVM_BOF_PATH
#define RVVM_BOF_PATH ""
#endif
#ifndef RVVM_BOF_BAD_PATH
#define RVVM_BOF_BAD_PATH ""
#endif
#ifndef RVVM_BOF_WIN_PATH
#define RVVM_BOF_WIN_PATH ""
#endif
#ifndef RVVM_BOF_LIB_PATH
#define RVVM_BOF_LIB_PATH ""
#endif
#ifndef RVVM_LIBANSWER_PATH
#define RVVM_LIBANSWER_PATH ""
#endif

/* Must match struct rv_bof_args in the module. */
typedef struct {
  const uint8_t *buf;
  size_t len;
} rv_lib;

typedef struct {
  const uint8_t *buf;
  size_t len;
  const rv_lib *libs;
  size_t nlibs;
} rv_bof_args;

typedef char *(*rv_run_fn)(const uint8_t *image, size_t image_len,
                           const char *entry, const rv_bof_args *args);
typedef const char *(*rv_last_fn)(void);
typedef int (*rv_code_fn)(void);
typedef void (*rv_free_fn)(char *);

static rv_run_fn g_run;
static rv_last_fn g_last;
static rv_code_fn g_code;
static rv_free_fn g_release;

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
    free(b);
    fclose(f);
    return NULL;
  }
  fclose(f);
  *len = (size_t)n;
  return b;
}

static int open_module(void) {
  size_t len = 0;
  uint8_t *img = slurp(RVVM_MODULE_PATH, &len);
  if (img == NULL) {
    fprintf(stderr, "cannot read %s\n", RVVM_MODULE_PATH);
    return -1;
  }
  char err[160];
  elfload_module *mod = elfload_map(img, len, err, sizeof(err));
  free(img);
  if (mod == NULL) {
    fprintf(stderr, "map %s: %s\n", RVVM_MODULE_PATH, err);
    return -1;
  }
  g_run = (rv_run_fn)elfload_sym(mod, "rv_run");
  g_last = (rv_last_fn)elfload_sym(mod, "rv_last_error");
  g_code = (rv_code_fn)elfload_sym(mod, "rv_exit_code");
  g_release = (rv_free_fn)elfload_sym(mod, "rv_free");
  if (g_run == NULL || g_last == NULL || g_code == NULL || g_release == NULL) {
    fprintf(stderr, "module is missing its exports\n");
    return -1;
  }
  return 0;
}

static char *bof_run(const uint8_t *img, size_t len, const char *entry,
                     const uint8_t *args, size_t args_len) {
  rv_bof_args a;
  a.buf = args;
  a.len = args_len;
  a.libs = NULL;
  a.nlibs = 0;
  return g_run(img, len, entry, &a);
}

static char *bof_run_lib(const uint8_t *img, size_t len, const char *entry,
                         const rv_lib *libs, size_t nlibs) {
  rv_bof_args a;
  a.buf = NULL;
  a.len = 0;
  a.libs = libs;
  a.nlibs = nlibs;
  return g_run(img, len, entry, &a);
}

int main(void) {
  if (open_module() != 0)
    return 1;

  size_t bof_len = 0;
  uint8_t *bof = slurp(RVVM_BOF_PATH, &bof_len);
  if (bof == NULL) {
    fprintf(stderr, "cannot read %s\n", RVVM_BOF_PATH);
    return 1;
  }
  size_t bad_len = 0;
  uint8_t *bad_bof = slurp(RVVM_BOF_BAD_PATH, &bad_len);
  if (bad_bof == NULL) {
    fprintf(stderr, "cannot read %s\n", RVVM_BOF_BAD_PATH);
    return 1;
  }

  /* Packed COFF arguments: u32 body length | u32 string length | "alpha\0". */
  static const uint8_t packed[] = {0x0a, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00,
                                   0x00, 'a',  'l',  'p',  'h',  'a',  0x00};
  char *out = bof_run(bof, bof_len, "go", packed, sizeof(packed));
  CHECK(out != NULL);
  CHECK(out != NULL && strcmp(out, "bof alpha (6)\n") == 0);
  CHECK_EQ_LONG(g_code(), 0);
  g_release(out);

  /* No arguments: the BOF still runs and sees an empty parser. */
  out = bof_run(bof, bof_len, "", NULL, 0);
  CHECK(out != NULL);
  CHECK(out != NULL && strcmp(out, "bof none\n") == 0);
  g_release(out);

  /* Windows BOF import convention: MODULE$Function resolves to the guest
   * runtime symbol of the same suffix. */
  size_t win_len = 0;
  uint8_t *win = slurp(RVVM_BOF_WIN_PATH, &win_len);
  CHECK(win != NULL);
  if (win != NULL) {
    out = bof_run(win, win_len, "go", NULL, 0);
    CHECK(out != NULL);
    CHECK(out != NULL && strcmp(out, "win ok\n") == 0);
    g_release(out);
    free(win);
  }

  /* A separately delivered RISC-V library is loaded into guest RAM and its
   * symbols resolve across objects. */
  {
    size_t llen = 0, blen = 0;
    uint8_t *lib = slurp(RVVM_LIBANSWER_PATH, &llen);
    uint8_t *lbof = slurp(RVVM_BOF_LIB_PATH, &blen);
    CHECK(lib != NULL && lbof != NULL);
    if (lib != NULL && lbof != NULL) {
      rv_lib l;
      l.buf = lib;
      l.len = llen;
      out = bof_run_lib(lbof, blen, "go", &l, 1);
      CHECK(out != NULL);
      CHECK(out != NULL && strcmp(out, "lib 42\n") == 0);
      g_release(out);
    }
    free(lib);
    free(lbof);
  }

  /* Missing export and a malformed object are rejected. */
  out = bof_run(bof, bof_len, "missing", packed, sizeof(packed));
  CHECK(out == NULL);
  CHECK(strstr(g_last(), "BOF export not found") != NULL);
  out = bof_run(bof, bof_len / 2, "go", packed, sizeof(packed));
  CHECK(out == NULL);

  /* Unresolved import names the symbol instead of running. */
  out = bof_run(bad_bof, bad_len, "go", NULL, 0);
  CHECK(out == NULL);
  CHECK(strstr(g_last(), "unresolved symbol no_such_symbol") != NULL);

  /* Header validation. */
  uint8_t *bad = (uint8_t *)malloc(bof_len);
  if (bad == NULL)
    return 1;
#define BAD_COPY()                                                             \
  do {                                                                         \
    memcpy(bad, bof, bof_len);                                                 \
  } while (0)
#define EXPECT_ERR(buf, n, needle)                                             \
  do {                                                                         \
    out = bof_run((buf), (n), "go", NULL, 0);                                  \
    CHECK(out == NULL);                                                        \
    CHECK(strstr(g_last(), (needle)) != NULL);                                 \
  } while (0)

  out = bof_run(NULL, 0, "go", NULL, 0);
  CHECK(out == NULL);
  CHECK(strstr(g_last(), "empty image") != NULL);

  BAD_COPY();
  EXPECT_ERR(bad, 8, "image too small");
  BAD_COPY();
  bad[0] = 0; /* not ELF */
  EXPECT_ERR(bad, bof_len, "not an ELF image");
  BAD_COPY();
  bad[4] = 2; /* ELFCLASS64 */
  EXPECT_ERR(bad, bof_len, "ELF32");
  BAD_COPY();
  bad[16] = 2; /* ET_EXEC */
  bad[17] = 0;
  EXPECT_ERR(bad, bof_len, "not a relocatable object");
  BAD_COPY();
  bad[18] = 0; /* e_machine = 0 */
  bad[19] = 0;
  EXPECT_ERR(bad, bof_len, "not a RISC-V image");
  BAD_COPY();
  bad[48] = 0; /* e_shnum = 0 */
  bad[49] = 0;
  EXPECT_ERR(bad, bof_len, "bad section headers");
  BAD_COPY();
  bad[32] = 0xff; /* e_shoff far past the image */
  bad[33] = 0xff;
  bad[34] = 0xff;
  bad[35] = 0x7f;
  EXPECT_ERR(bad, bof_len, "bad section headers");

  free(bad);
  free(bof);
  free(bad_bof);
  TEST_DONE();
}
