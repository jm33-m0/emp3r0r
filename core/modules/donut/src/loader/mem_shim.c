/* Freestanding helpers for the Donut loader stub.
 *
 * Clang lowers struct copies and small loop idioms to memcpy/memset/memmove
 * even in freestanding builds. Donut's clib.c provides Memcpy/Memset under its
 * own names, so the loader needs the standard symbols to link without a CRT.
 * This file is a local addition to the vendored Donut source. */
#include <stddef.h>

void *memcpy(void *dst, const void *src, size_t n) {
  unsigned char *d = (unsigned char *)dst;
  const unsigned char *s = (const unsigned char *)src;
  while (n--) {
    *d++ = *s++;
  }
  return dst;
}

void *memset(void *dst, int c, size_t n) {
  unsigned char *d = (unsigned char *)dst;
  while (n--) {
    *d++ = (unsigned char)c;
  }
  return dst;
}

void *memmove(void *dst, const void *src, size_t n) {
  unsigned char *d = (unsigned char *)dst;
  const unsigned char *s = (const unsigned char *)src;
  if (d < s) {
    while (n--) {
      *d++ = *s++;
    }
  } else {
    d += n;
    s += n;
    while (n--) {
      *--d = *--s;
    }
  }
  return dst;
}
