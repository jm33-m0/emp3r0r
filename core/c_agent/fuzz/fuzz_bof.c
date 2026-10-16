#include "bof.h"

#include "fuzz_common.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef FUZZ_BOF_LOADER
#define FUZZ_BOF_LOADER ""
#endif

/* The loader reads arbitrary bytes as a relocatable object, so the property
 * under test is memory safety of the ELF/relocation parser. The real
 * coffloader_linux image is read once and reused. */
static uint8_t *g_loader = NULL;
static size_t g_loader_len = 0;
static int g_loader_tried = 0;

static void load_once(void) {
  if (g_loader_tried)
    return;
  g_loader_tried = 1;
  if (FUZZ_BOF_LOADER[0] == '\0')
    return;
  FILE *f = fopen(FUZZ_BOF_LOADER, "rb");
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
  g_loader = (uint8_t *)malloc((size_t)n);
  if (g_loader != NULL && fread(g_loader, 1, (size_t)n, f) == (size_t)n)
    g_loader_len = (size_t)n;
  else {
    free(g_loader);
    g_loader = NULL;
  }
  fclose(f);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  load_once();
  if (g_loader == NULL)
    return 0;

  char *out = NULL;
  (void)c2_bof_run(g_loader, g_loader_len, data, size, "go", NULL, 0, &out);
  free(out);
  return 0;
}
