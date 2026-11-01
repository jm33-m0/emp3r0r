#include "fuzz_common.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * The rvvm interpreter loads an untrusted static RV32 executable, maps its
 * segments and runs it behind one Linux syscall gate. The property under test
 * is memory safety: no image may make the loader or the interpreter read or
 * write outside the guest arena, the output buffer or the image itself.
 *
 * Inputs take two paths:
 *   1. as the whole image, which exercises ELF and program header validation;
 *   2. patched into a known-good executable, alternating between its code area
 *      and its ELF/program-header area, which pushes arbitrary data through the
 *      loader, the decoder and the syscall gate.
 *
 * The Makefile builds this target with a small instruction budget so a single
 * input cannot spend the fuzzer's time budget.
 */

#ifndef RVVM_SEED
#define RVVM_SEED ""
#endif

/* Must match struct rv_bof_args in the interpreter module. */
typedef struct {
  const uint8_t *buf;
  size_t len;
  const uint8_t *env;
  size_t env_len;
} rv_bof_args;

extern char *Run(const uint8_t *image, size_t len, const rv_bof_args *args);
extern void Free(char *out);

static uint8_t *g_seed = NULL;
static size_t g_seed_len = 0;
static uint8_t *g_img = NULL;
static int g_tried = 0;
static unsigned g_calls = 0;

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
  /* Fuzz the environment-block parser as well as the argument parser. */
  a.env = args;
  a.env_len = args_len;
  return Run(image, len, &a);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  load_seed();

  char *out = run(data, size, NULL, 0);
  Free(out);

  if (g_seed != NULL && g_seed_len > 0x1100 && size > 0) {
    memcpy(g_img, g_seed, g_seed_len);
    /* Alternate between the code area and the ELF/program-header area so the
     * loader's validation runs against mutated input as well. */
    size_t off = (g_calls++ & 1u) ? 0x1000u : 0x34u;
    size_t n = size < g_seed_len - off ? size : g_seed_len - off;
    if (n > 4096)
      n = 4096;
    memcpy(g_img + off, data, n);
    out = run(g_img, g_seed_len, data, size < 4096 ? size : 4096);
    Free(out);
  }
  return 0;
}
