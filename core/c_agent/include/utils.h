#ifndef C2_UTILS_H
#define C2_UTILS_H

/*
 * utils.h — freestanding platform helpers shared by the stager and the agent.
 *
 * Two families live here:
 *   - compile-time mmap/mprotect constants and page helpers, usable anywhere;
 *   - raw-syscall-backed replacements for a handful of libc entry points
 *     (write/close/exit/open/read/mmap/...), implemented in src/system.c.
 *
 * The libc replacements are for -nostdlib payloads only. A hosted agent links
 * libc and must not link src/system.c; include this header freely for the
 * constants, but link the matching source only in freestanding builds.
 *
 * This header intentionally does not re-export strings.h or debug.h: include
 * them directly where their symbols are used.
 */

#include <stddef.h>

// Page size for mmap/mprotect alignment (4 KiB on all supported targets).
#ifndef PAGE_SIZE
#define PAGE_SIZE 0x1000
#endif

// Round a byte length up to a whole number of pages.
#define PAGE_ALIGN_UP(x) (((x) + PAGE_SIZE - 1) & ~(size_t)(PAGE_SIZE - 1))

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

// open() flags
#ifndef O_RDONLY
#define O_RDONLY 0
#endif

// Libc replacements (src/system.c). Only for -nostdlib payloads.
long write(int fd, const void *buf, size_t count);
long close(int fd);
void exit(int error_code);
int open(const char *path, int flags, ...);
long read(int fd, void *buf, size_t count);
void *mmap(void *addr, size_t length, int prot, int flags, int fd, long offset);
long munmap(void *addr, size_t length);
long mprotect(void *addr, size_t len, int prot);

#endif /* C2_UTILS_H */
