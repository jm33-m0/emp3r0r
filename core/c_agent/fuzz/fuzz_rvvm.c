#include "fuzz_common.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * The rvvm interpreter parses an untrusted RV32 ET_REL object, relocates it
 * against its embedded guest runtime, and executes it. The property under test
 * is memory safety: no image may make the loader or the interpreter read or
 * write outside the guest arena, the output buffer or the image itself.
 *
 * Inputs take two paths:
 *   1. as the whole BOF image, which exercises ELF section/symbol/relocation
 *      parsing;
 *   2. patched into a known-good BOF's code/data area, which pushes arbitrary
 *      instruction words through the decoder and the host-call mailbox.
 *
 * The Makefile builds this target with a small RV_MAX_INSNS so a single input
 * cannot spend the fuzzer's time budget.
 */

#ifndef RVVM_SEED
#define RVVM_SEED ""
#endif

/* Must match struct rv_bof_args in the interpreter module. */
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

extern char *rv_run(const uint8_t *image, size_t len, const char *entry,
                    const rv_bof_args *args);
extern const char *rv_last_error(void);
extern void rv_free(char *out);

static uint8_t *g_seed = NULL;
static size_t g_seed_len = 0;
static uint8_t *g_img = NULL;
static int g_tried = 0;

static void load_seed(void) {
  if (g_tried)
    return;
  g_tried = 1;
  if (RVVM_SEED[0] == '\0')
    return;
  FILE *f = fopen(RVVM_SEED, "rb");
  if (f == NULL)
    return;
  if (fseek(f, 0, SEEK_END) != 0) {
    fclose(f);
    return;
  }
  long n = ftell(f);
  if (n <= 0 || fseek(f, 0, SEEK_SET) != 0) {
    fclose(f);
    return;
  }
  g_seed = (uint8_t *)malloc((size_t)n);
  g_img = (uint8_t *)malloc((size_t)n);
  if (g_seed != NULL && g_img != NULL &&
      fread(g_seed, 1, (size_t)n, f) == (size_t)n)
    g_seed_len = (size_t)n;
  else {
    free(g_seed);
    free(g_img);
    g_seed = NULL;
    g_img = NULL;
  }
  fclose(f);
}

static char *run(const uint8_t *image, size_t len, const uint8_t *args,
                 size_t args_len) {
  rv_bof_args a;
  a.buf = args;
  a.len = args_len;
  a.libs = NULL;
  a.nlibs = 0;
  return rv_run(image, len, "go", &a);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  load_seed();

  char *out = run(data, size, NULL, 0);
  rv_free(out);

  if (g_seed != NULL && size > 0) {
    memcpy(g_img, g_seed, g_seed_len);
    /* Patch past the ELF header so the section headers usually stay valid and
     * the input reaches the decoder. */
    size_t off = 0x40;
    if (off < g_seed_len) {
      size_t n = size < g_seed_len - off ? size : g_seed_len - off;
      memcpy(g_img + off, data, n);
    }
    out = run(g_img, g_seed_len, data, size < 4096 ? size : 4096);
    rv_free(out);
  }
  return 0;
}
