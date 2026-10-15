#ifndef UTIL_DYNLOAD_H
#define UTIL_DYNLOAD_H

#include <stddef.h>

/*
 * dynload.h — runtime resolution of libc's dl* entry points and stateless ELF
 * dynamic-symbol lookup.
 *
 * A payload may need a shared library that is already present on the target
 * (libcrypto, libcurl, libssl, ...) without linking against it. libdl.so.2 is
 * not required: the public dlopen/dlsym/dlclose are resolved from libc (glibc
 * >= 2.34) or the glibc-internal __libc_* names (older glibc).
 *
 * The resolved pointers are caller-owned because the freestanding stager image
 * is mapped RX and cannot hold a writable global. A hosted agent can use the
 * process-wide context from src/util/dynload_hosted.c.
 */

typedef void *(*dlopen_fn)(const char *, int);
typedef void *(*dlsym_fn)(void *, const char *);
typedef int (*dlclose_fn)(void *);

/* dlopen() flags (Linux/glibc). */
#ifndef RTLD_LAZY
#define RTLD_LAZY 1
#endif
#ifndef RTLD_NOW
#define RTLD_NOW 2
#endif
#ifndef RTLD_GLOBAL
#define RTLD_GLOBAL 0x100
#endif
#ifndef RTLD_LOCAL
#define RTLD_LOCAL 0
#endif

/* Caller-owned resolution cache. Zero it (or call dynload_reset) before use. */
typedef struct dynload {
  int resolved;
  dlopen_fn open;
  dlsym_fn sym;
  dlclose_fn close;
} dynload;

/* Reset a context so the next dynload_open/sym/close resolves afresh. */
void dynload_reset(dynload *dl);

/* ---- stateless ELF helpers ---------------------------------------------- */

/*
 * First mapping in /proc/self/maps whose pathname contains `needle` (e.g.
 * "libc.so" or "libc-"). Returns its base and, when `end` is non-NULL, stores
 * the end of the module's contiguous mapping run. Returns 0 when not found.
 */
unsigned long dynload_find_module(const char *needle, unsigned long *end);

/*
 * Pure parser over a length-delimited /proc/self/maps buffer (the input need
 * not be NUL-terminated): first mapping whose pathname contains `needle`, with
 * the module's mapping end in `*end`. The file-backed finders use the same
 * parser; exposed so the unit test and fuzz/fuzz_maps.c can drive it with
 * arbitrary text.
 */
unsigned long dynload_maps_find(const char *text, size_t len,
                                const char *needle, unsigned long *end);

/* libc.so.6 / libc-2.17.so base and mapping end; returns 0 when not found. */
unsigned long dynload_find_libc(unsigned long *end);

/*
 * Resolve a dynamic symbol `name` in the ELF image occupying [base, base+len).
 * Every header, table and pointer is bounds-checked against that range and the
 * module's PT_LOAD segments, so malformed or truncated input can only fail,
 * never read out of bounds. DT_* pointers may be relocated absolute addresses
 * (loaded module) or base-relative offsets (flat image); either is accepted.
 * Returns the relocated address, or NULL. Fuzzed by fuzz/fuzz_dynload.c.
 *
 * Use dynload_find_module/dynload_find_libc to obtain a trusted range for a
 * loaded module.
 */
void *dynload_resolve_module(const void *base, size_t len, const char *name);

/* ---- context API --------------------------------------------------------- */

/* Resolve the configured dl* symbols from libc into *dl. 0 on success. */
int dynload_resolve(dynload *dl);

/* Lazy convenience wrappers over a caller-owned context. */
void *dynload_open(dynload *dl, const char *soname, int flags);
void *dynload_sym(dynload *dl, void *handle, const char *name);
int dynload_close(dynload *dl, void *handle);

/*
 * Process-wide context for hosted binaries. Defined only by
 * src/util/dynload_hosted.c, which freestanding payloads must not link (it has a
 * writable global). First use is not thread-safe.
 */
dynload *dynload_hosted(void);

/* ---- build-time configuration (overridable with -D) ---------------------- */

/*
 * DYNLOAD_MODE selects which libc names to resolve; they are looked up in the
 * libc segment (glibc's libc.so.6 or the musl loader, see dynload_find_libc),
 * never in libdl.so.2.
 *   DYNLOAD_MODE_PUBLIC  (0): dlopen/dlsym/dlclose (glibc >= 2.34 and musl).
 *   DYNLOAD_MODE_LIBC_DL (1): __libc_dlopen_mode/__libc_dlsym/__libc_dlclose
 *                             (glibc < 2.34; absent on musl, which has no libdl
 *                             and only exports the public names).
 *   DYNLOAD_MODE_AUTO    (2): resolve libc_dl, falling back to the public
 *                             names when the glibc-internal ones are absent.
 * PUBLIC is the default when the macro is not set, so a plain hosted build
 * (e.g. the unit tests) uses the host libc; the Makefile always passes an
 * explicit -DDYNLOAD_MODE for the agent.
 */
#define DYNLOAD_MODE_PUBLIC 0
#define DYNLOAD_MODE_LIBC_DL 1
#define DYNLOAD_MODE_AUTO 2
#ifndef DYNLOAD_MODE
#define DYNLOAD_MODE DYNLOAD_MODE_PUBLIC
#endif

/*
 * DYNLOAD_HASH_STYLE selects the dynamic-symbol hash table to use.
 *   DYNLOAD_HASH_AUTO (0): DT_HASH if present, else DT_GNU_HASH.
 *   DYNLOAD_HASH_SYSV (1): DT_HASH only.
 *   DYNLOAD_HASH_GNU  (2): DT_GNU_HASH only.
 */
#define DYNLOAD_HASH_AUTO 0
#define DYNLOAD_HASH_SYSV 1
#define DYNLOAD_HASH_GNU 2
#ifndef DYNLOAD_HASH_STYLE
#define DYNLOAD_HASH_STYLE DYNLOAD_HASH_AUTO
#endif

#endif /* UTIL_DYNLOAD_H */
