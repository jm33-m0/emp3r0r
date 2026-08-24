#include "syscalls.h"
#include "utils.h"

/* mmap a dedicated read/write page for the stager's mutable state and bind it
 * to %r15 (see state.h). Uses the embedded syscall gadget directly because the
 * cached vDSO gadget is not resolved yet. */
void stager_state_init(void) {
  struct stager_state *st;
  long ret;
  void *gadget = get_embedded_syscall_gadget();
  register long r10 __asm__("r10") = MAP_PRIVATE | MAP_ANONYMOUS;
  register long r8 __asm__("r8") = -1;
  register long r9 __asm__("r9") = 0;

  __asm__ __volatile__("call *%1"
                       : "=a"(ret)
                       : "r"(gadget), "a"((long)SYS_mmap), "D"((long)0),
                         "S"((long)0x1000), "d"((long)(PROT_READ | PROT_WRITE)),
                         "r"(r10), "r"(r8), "r"(r9)
                       : "rcx", "r11", "memory");
  if (ret < 0)
    __builtin_trap();

  st = (struct stager_state *)ret;
  st->syscall_gadget = _SYSCALL_GADGET_UNRESOLVED;
  st->dl_ready = 1;
  st->dlopen_ = 0;
  st->dlsym_ = 0;
  st->dlclose_ = 0;

  __asm__ __volatile__("mov %0, %%r15" : : "r"(st) : "r15", "memory");
}

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

int strcmp(const char *s1, const char *s2) {
  while (*s1 && (*s1 == *s2)) {
    s1++;
    s2++;
  }
  return *(const unsigned char *)s1 - *(const unsigned char *)s2;
}

char *strstr(const char *haystack, const char *needle) {
  if (*needle == '\0')
    return (char *)haystack;
  for (; *haystack; haystack++) {
    const char *h = haystack;
    const char *n = needle;
    while (*h && *n && *h == *n) {
      h++;
      n++;
    }
    if (*n == '\0')
      return (char *)haystack;
  }
  return NULL;
}

long write(int fd, const void *buf, size_t count) {
  return syscall3(SYS_write, fd, (long)buf, count);
}

long close(int fd) { return syscall1(SYS_close, fd); }

void exit(int error_code) { syscall1(SYS_exit, error_code); }

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
