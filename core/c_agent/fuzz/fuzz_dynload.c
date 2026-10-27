#include "util/dynload.h"

#include "fuzz_common.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/*
 * Feed arbitrary bytes to the bounds-checked ELF resolver as if they were a
 * mapped module. The input is copied into an exact-size heap buffer so ASan's
 * redzones catch any read before or after the declared range; a parser that
 * trusts the header would fault here.
 */
/* Keep the copy in its own noinline helper: GCC's -Wmaybe-uninitialized fires
 * spuriously when a heap pointer crosses a translation unit under ASan, so
 * isolating it here keeps the fuzz harness warning-clean under -Werror. */
static __attribute__((noinline)) uint8_t *copy_input(const uint8_t *data,
                                                     size_t size) {
  uint8_t *b = (uint8_t *)malloc(size ? size : 1);
  if (b == NULL)
    return NULL;
  if (size)
    memcpy(b, data, size);
  return b;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  uint8_t *buf = copy_input(data, size);
  if (buf == NULL)
    return 0;

  static const char *const names[] = {"malloc", "free",   "dlopen",
                                      "dlsym",  "g_free", "x"};
  (void)dynload_resolve_module(
      buf, size, names[size % (sizeof(names) / sizeof(names[0]))]);

  /* A name taken from the input exercises the bounded strtab comparison. */
  char name[32];
  size_t n = size < sizeof(name) - 1 ? size : sizeof(name) - 1;
  if (n) {
    memcpy(name, data, n);
    name[n] = '\0';
    (void)dynload_resolve_module(buf, size, name);
  }

  free(buf);
  return 0;
}
