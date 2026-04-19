#include "syscalls.h"
#include "utils.h"

#include <stdarg.h>

void *_cached_syscall_gadget __attribute__((visibility("hidden"))) = (void *)1;

void *memcpy(void *dest, const void *src, size_t n) {
  unsigned char *d = (unsigned char *)dest;
  const unsigned char *s = (const unsigned char *)src;
  if (d == s || n == 0)
    return dest;

  if ((uintptr_t)d < (uintptr_t)s) {
    while (n--)
      *d++ = *s++;
  } else {
    d += n;
    s += n;
    while (n--)
      *--d = *--s;
  }
  return dest;
}

void *memset(void *s, int c, size_t n) {
  unsigned char *p = (unsigned char *)s;
  while (n--)
    *p++ = (unsigned char)c;
  return s;
}

size_t strlen(const char *s) {
  size_t len = 0;
  while (*s++)
    len++;
  return len;
}

int strncmp(const char *s1, const char *s2, size_t n) {
  while (n && *s1 && (*s1 == *s2)) {
    s1++;
    s2++;
    n--;
  }
  if (n == 0)
    return 0;
  return *(const unsigned char *)s1 - *(const unsigned char *)s2;
}

char *strstr(const char *haystack, const char *needle) {
  size_t nlen = strlen(needle);
  if (nlen == 0)
    return (char *)haystack;
  size_t hlen = strlen(haystack);
  if (hlen < nlen)
    return NULL;

  for (size_t i = 0; i <= hlen - nlen; i++) {
    if (strncmp(haystack + i, needle, nlen) == 0) {
      return (char *)(haystack + i);
    }
  }
  return NULL;
}

long getrandom(void *buf, size_t buflen, unsigned int flags) {
  return syscall3(SYS_getrandom, (long)buf, buflen, flags);
}

long write(int fd, const void *buf, size_t count) {
  return syscall3(SYS_write, fd, (long)buf, count);
}

long close(int fd) { return syscall1(SYS_close, fd); }

long exit(int error_code) { return syscall1(SYS_exit, error_code); }

void *mmap(void *addr, size_t length, int prot, int flags, int fd,
           long offset) {
  return (void *)syscall6(SYS_mmap, (long)addr, length, prot, flags, fd,
                          offset);
}

long munmap(void *addr, size_t length) {
  return syscall2(SYS_munmap, (long)addr, length);
}

long mprotect(void *addr, size_t len, int prot) {
  return syscall3(SYS_mprotect, (long)addr, len, prot);
}

#ifdef DEBUG
void debug_print(const char *format, ...) { (void)format; }

void perror(const char *s) { (void)s; }
#endif
