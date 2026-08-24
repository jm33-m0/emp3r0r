#ifndef DYNLOAD_H
#define DYNLOAD_H

#include <stddef.h>
#include <stdint.h>

/*
 * Runtime dynamic loading for freestanding PIC stagers.
 *
 * The stager is built -nostdlib and extracted as raw shellcode, so libc and
 * the dynamic linker are not linked in. These helpers resolve dlopen/dlsym/
 * dlclose from libc at runtime and expose them to transports, so a transport
 * can load a library that is already present on the target (libcurl, libssl,
 * ...) without linking against it.
 *
 * Example:
 *   void *h = dynload_open("libcurl.so.4", RTLD_NOW | RTLD_LOCAL);
 *   void *f = dynload_sym(h, "curl_easy_init");
 *   dynload_close(h);
 */

/* dlopen() flags (Linux/glibc). */
#define RTLD_LAZY 1
#define RTLD_NOW 2
#define RTLD_GLOBAL 0x100
#define RTLD_LOCAL 0

/* dlopen() a library by soname. Returns a handle, or NULL on failure. */
void *dynload_open(const char *soname, int flags);

/* dlsym() a symbol from a dynload_open() handle, or NULL on failure. */
void *dynload_sym(void *handle, const char *name);

/* dlclose() a dynload_open() handle. Returns 0 on success. */
int dynload_close(void *handle);

/* Find libc's base address by scanning /proc/self/maps (0 on failure). */
unsigned long dynload_find_libc(void);

/* Resolve a dynamic symbol `name` from the ELF module loaded at `base`.
 * Useful for symbols not reachable through a dlopen() handle. */
void *dynload_resolve_module(void *base, const char *name);

#endif /* DYNLOAD_H */
