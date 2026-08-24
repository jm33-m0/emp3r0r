#ifndef UTILS_H
#define UTILS_H

#include <stddef.h>
#include <stdint.h>

// Memory protection
#define PROT_NONE 0x0
#define PROT_READ 0x1
#define PROT_WRITE 0x2
#define PROT_EXEC 0x4

// Map flags
#define MAP_SHARED 0x01
#define MAP_PRIVATE 0x02
#define MAP_FIXED 0x10
#define MAP_ANONYMOUS 0x20
#define MAP_ANON MAP_ANONYMOUS
#define MAP_FAILED ((void *)-1)

// Libc replacements
void *memcpy(void *dest, const void *src, size_t n);
void *memset(void *s, int c, size_t n);
size_t strlen(const char *s);
long write(int fd, const void *buf, size_t count);
long close(int fd);
long exit(int error_code);
void *mmap(void *addr, size_t length, int prot, int flags, int fd, long offset);
long munmap(void *addr, size_t length);
long mprotect(void *addr, size_t len, int prot);

#ifdef DEBUG
void debug_print(const char *format, ...);
void perror(const char *s);
#else
#define debug_print(...)                                                       \
  do {                                                                         \
  } while (0)
#define perror(s)                                                              \
  do {                                                                         \
  } while (0)
#endif

#endif
