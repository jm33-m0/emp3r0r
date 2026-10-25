#include "util/dynload.h"

#include "fuzz_common.h"

#include <stdint.h>
#include <string.h>

/*
 * Drive the /proc/self/maps parser with arbitrary text and needles. The
 * property under test is that malformed text (huge fields, missing path,
 * truncated lines, non-NUL-terminated input) can only produce a result, never
 * read out of bounds. The file-backed stager finders run the same parser.
 */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  static const char *const needles[] = {
      "libc.so", "libc-", "libc", "", "/usr/lib/x86_64-linux-gnu/libc.so.6"};
  unsigned long end = 0;
  for (size_t i = 0; i < sizeof(needles) / sizeof(needles[0]); i++)
    (void)dynload_maps_find((const char *)data, size, needles[i], &end);

  /* A needle taken from the input exercises basename matching on arbitrary
   * haystacks. */
  char needle[64];
  size_t n = size < sizeof(needle) - 1 ? size : sizeof(needle) - 1;
  if (n) {
    memcpy(needle, data, n);
    needle[n] = '\0';
    (void)dynload_maps_find((const char *)data, size, needle, &end);
  }
  return 0;
}
