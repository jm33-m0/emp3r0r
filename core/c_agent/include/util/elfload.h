#ifndef UTIL_ELFLOAD_H
#define UTIL_ELFLOAD_H

#include <stddef.h>
#include <stdint.h>

/*
 * elfload.h — map an ET_DYN ELF64 shared object from memory and run it.
 *
 * This is the C counterpart of the Go agent's core/lib/memmod. Its PT_LOAD
 * segments are mmap'd anonymously, its dynamic relocations are applied against
 * the host's already loaded libraries, and the segments are made executable.
 * The mapping is released with elfload_free.
 *
 * Used by bof.c to run the coffloader_linux dependency in memory.
 */

typedef struct elfload_module elfload_module;

/*
 * Map and relocate an ELF64 image of `len` bytes. Returns NULL on malformed
 * input, an unsupported machine/relocation, or an unresolved external symbol,
 * writing a short reason to `err` (when non-NULL).
 */
elfload_module *elfload_map(const uint8_t *image, size_t len, char *err,
                            size_t err_cap);

/* Resolve an exported dynamic symbol in the mapped module, or NULL. */
void *elfload_sym(const elfload_module *m, const char *name);

/* Unmap the module. NULL is a no-op. */
void elfload_free(elfload_module *m);

#endif /* UTIL_ELFLOAD_H */
