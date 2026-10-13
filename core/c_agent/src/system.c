/*
 * system.c — raw-syscall libc replacements.
 *
 * Linked only into -nostdlib payloads (the stager). A hosted agent links libc
 * instead; do not compile this file into it.
 *
 * `open` is variadic to match the libc prototype. When O_CREAT is absent the
 * mode argument is ignored by the kernel; callers should still pass it so the
 * freestanding implementation reads a defined value from the varargs list.
 */

#include "syscalls.h"
#include "utils.h"

#include <stdarg.h>

long write(int fd, const void *buf, size_t count) {
  return syscall3(SYS_write, fd, (long)buf, count);
}

long close(int fd) { return syscall1(SYS_close, fd); }

void exit(int error_code) { syscall1(SYS_exit, error_code); }

int open(const char *path, int flags, ...) {
  va_list ap;
  unsigned int mode;
  va_start(ap, flags);
  /* mode_t is an unsigned int and is only meaningful with O_CREAT; reading it
   * as int matches the libc variadic ABI. */
  mode = va_arg(ap, unsigned int);
  va_end(ap);
  return (int)syscall3(SYS_open, (long)path, flags, (long)mode);
}

long read(int fd, void *buf, size_t count) {
  return syscall3(SYS_read, fd, (long)buf, count);
}

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
