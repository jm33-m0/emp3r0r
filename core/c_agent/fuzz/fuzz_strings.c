#include "util/strings.h"

#include "fuzz_common.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/*
 * The freestanding string/memory primitives are linked into -nostdlib payloads
 * that parse untrusted network data, so they must match libc's observable
 * behaviour exactly. This is a differential target: every call is compared
 * against a byte-wise reference computed here (the parser's own functions are
 * used by nothing in the comparison because strings.c overrides libc symbols).
 *
 * Inputs are always NUL-terminated copies on the heap, so ASan also catches any
 * read past the terminator.
 */
static size_t ref_strlen(const char *s) {
  size_t n = 0;
  while (s[n])
    n++;
  return n;
}

static int ref_strcmp(const char *a, const char *b) {
  while (*a && *a == *b) {
    a++;
    b++;
  }
  return (int)(unsigned char)*a - (int)(unsigned char)*b;
}

static const char *ref_strstr(const char *h, const char *n) {
  if (*n == '\0')
    return h;
  for (; *h; h++) {
    const char *p = h;
    const char *q = n;
    while (*p && *q && *p == *q) {
      p++;
      q++;
    }
    if (*q == '\0')
      return h;
  }
  return NULL;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  /* NUL-terminated needles/haystacks: split the input at the first NUL so the
   * two halves differ, and cap so both are valid C strings. */
  char a[512], b[512];
  size_t n = size < sizeof(a) - 1 ? size : sizeof(a) - 1;
  if (n)
    memcpy(a, data, n);
  a[n] = '\0';

  size_t m = (size - n) < sizeof(b) - 1 ? (size - n) : sizeof(b) - 1;
  if (m)
    memcpy(b, data + n, m);
  b[m] = '\0';

  if (strlen(a) != ref_strlen(a))
    c2_fuzz_fail("strlen mismatch");
  if (strcmp(a, b) != ref_strcmp(a, b))
    c2_fuzz_fail("strcmp mismatch");
  if (strstr(a, b) != ref_strstr(a, b))
    c2_fuzz_fail("strstr mismatch");

  /* memcpy/memset on a small heap buffer, compared to a byte-wise copy. */
  size_t cap = size % (sizeof(a) + 1);
  unsigned char *dst = (unsigned char *)malloc(cap ? cap : 1);
  unsigned char *ref = (unsigned char *)malloc(cap ? cap : 1);
  if (dst == NULL || ref == NULL)
    c2_fuzz_fail("alloc");
  for (size_t i = 0; i < cap; i++) {
    unsigned char v = (unsigned char)(i * 7u + (size ? data[i % size] : 0));
    dst[i] = 0;
    ref[i] = 0;
    (void)v;
  }
  if (cap) {
    memset(dst, 0xA5, cap);
    for (size_t i = 0; i < cap; i++)
      ref[i] = 0xA5;
    if (dst[0] != 0xA5 || dst[cap - 1] != 0xA5)
      c2_fuzz_fail("memset mismatch");
    memcpy(dst, a, cap < strlen(a) ? cap : strlen(a));
    for (size_t i = 0; i < (cap < strlen(a) ? cap : strlen(a)); i++) {
      if (dst[i] != (unsigned char)a[i])
        c2_fuzz_fail("memcpy mismatch");
    }
  }
  free(dst);
  free(ref);

  return 0;
}
