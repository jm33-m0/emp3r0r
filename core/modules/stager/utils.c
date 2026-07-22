#include "utils.h"
#include "syscalls.h"
#include <stdarg.h>

/* Single shared instance of the syscall gadget cache.
 * Initialized to non-zero to force placement in .data (not .bss).
 * See syscalls.h for the extern declaration. */
void *_cached_syscall_gadget __attribute__((visibility("hidden"))) = (void *)1;

// -----------------------------------------------------------------------------
// Memory Management (Stateless mmap-based allocator)
// -----------------------------------------------------------------------------

void *malloc(size_t size) {
  if (size == 0)
    return NULL;

  // Allocate size + metadata (size_t)
  size_t total_size = size + sizeof(size_t);

  // Round up to page size (4096) to be nice to the kernel, though mmap does
  // this anyway But we need to know the exact size we asked for to unmap it
  // later? Actually, munmap requires the length. If we store the user size, we
  // can calculate total_size. But mmap operates on pages.

  long ret = syscall6(SYS_mmap, 0, total_size, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

  if (ret < 0) // Check for error (negative value)
    return NULL;

  void *ptr = (void *)ret;
  *(size_t *)ptr = size; // Store the requested size

  return (uint8_t *)ptr + sizeof(size_t);
}

void free(void *ptr) {
  if (!ptr)
    return;

  uint8_t *real_ptr = (uint8_t *)ptr - sizeof(size_t);
  size_t size = *(size_t *)real_ptr;
  size_t total_size = size + sizeof(size_t);

  syscall2(SYS_munmap, (long)real_ptr, total_size);
}

void *calloc(size_t nmemb, size_t size) {
  size_t total = nmemb * size;
  // mmap returns zeroed memory, so we don't strictly need memset,
  // but to be safe and standard compliant (if we switch allocator later):
  void *ptr = malloc(total);
  if (ptr) {
    memset(ptr, 0, total);
  }
  return ptr;
}

void *realloc(void *ptr, size_t size) {
  if (!ptr)
    return malloc(size);
  if (size == 0) {
    free(ptr);
    return NULL;
  }

  uint8_t *real_ptr = (uint8_t *)ptr - sizeof(size_t);
  size_t old_size = *(size_t *)real_ptr;

  size_t old_total = old_size + sizeof(size_t);
  size_t new_total = size + sizeof(size_t);

  size_t page_size = 4096;
  size_t old_aligned = (old_total + page_size - 1) & ~(page_size - 1);
  size_t new_aligned = (new_total + page_size - 1) & ~(page_size - 1);

  if (old_aligned == new_aligned) {
    *(size_t *)real_ptr = size;
    return ptr;
  }

  long ret = syscall6(SYS_mremap, (long)real_ptr, old_aligned, new_aligned,
                      1 /* MREMAP_MAYMOVE */, 0, 0);
  if (ret < 0 || ret == -1) {
    void *new_ptr = malloc(size);
    if (!new_ptr)
      return NULL;
    size_t copy_size = old_size < size ? old_size : size;
    memcpy(new_ptr, ptr, copy_size);
    free(ptr);
    return new_ptr;
  }

  uint8_t *new_real_ptr = (uint8_t *)ret;
  *(size_t *)new_real_ptr = size;
  return new_real_ptr + sizeof(size_t);
}

// -----------------------------------------------------------------------------
// String / Memory
// -----------------------------------------------------------------------------

void *memcpy(void *dest, const void *src, size_t n) {
  unsigned char *d = (unsigned char *)dest;
  const unsigned char *s = (const unsigned char *)src;

  if (d == s || n == 0)
    return dest;

  // Handle overlap (memmove semantics)
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

// -----------------------------------------------------------------------------
// Random
// -----------------------------------------------------------------------------

long getrandom(void *buf, size_t buflen, unsigned int flags) {
  return syscall3(SYS_getrandom, (long)buf, buflen, flags);
}

// -----------------------------------------------------------------------------
// Syscall Wrappers
// -----------------------------------------------------------------------------

long write(int fd, const void *buf, size_t count) {
  return syscall3(SYS_write, fd, (long)buf, count);
}

long read(int fd, void *buf, size_t count) {
  return syscall3(SYS_read, fd, (long)buf, count);
}

long close(int fd) { return syscall1(SYS_close, fd); }

long open(const char *pathname, int flags, int mode) {
  return syscall3(SYS_open, (long)pathname, flags, mode);
}

long lseek(int fd, long offset, int whence) {
  return syscall3(SYS_lseek, fd, offset, whence);
}

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

long fork(void) { return syscall0(SYS_fork); }

long pipe(int pipefd[2]) { return syscall1(SYS_pipe, (long)pipefd); }

long dup2(int oldfd, int newfd) { return syscall2(SYS_dup2, oldfd, newfd); }

long waitpid(int pid, int *status, int options) {
  return syscall4(SYS_wait4, pid, (long)status, options, 0);
}

long getuid(void) { return syscall0(SYS_getuid); }

long geteuid(void) { return syscall0(SYS_geteuid); }

long getgid(void) { return syscall0(SYS_getgid); }

long getegid(void) { return syscall0(SYS_getegid); }

long kill(int pid, int sig) { return syscall2(SYS_kill, pid, sig); }

long nanosleep(const struct timespec *req, struct timespec *rem) {
  return syscall2(SYS_nanosleep, (long)req, (long)rem);
}

int sigaction(int signum, const struct sigaction *act,
              struct sigaction *oldact) {
  return syscall4(SYS_rt_sigaction, signum, (long)act, (long)oldact,
                  sizeof(sigset_t));
}

int sigemptyset(sigset_t *set) {
  if (set == NULL)
    return -1;
  memset(set, 0, sizeof(sigset_t));
  return 0;
}
