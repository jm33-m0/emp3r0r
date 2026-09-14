/*
 * reflect - minimal in-memory PE (DLL) loader used to stage the staged_loader
 * payload. See reflect.c for the contract and safety notes.
 */
#ifndef STAGED_LOADER_REFLECT_H
#define STAGED_LOADER_REFLECT_H

#include <stddef.h>

/*
 * reflect_load maps a PE image from memory, applies relocations, resolves
 * imports, fixes section protections, sets up TLS and runs DllMain with
 * DLL_PROCESS_ATTACH. Returns the mapped base address, or NULL on any
 * malformed image or mapping failure.
 */
void *reflect_load(const unsigned char *image, size_t image_len);

/*
 * reflect_export resolves a named export from a reflect_load'd image.
 * Returns NULL if the image or export is missing.
 */
void *reflect_export(void *base, const char *name);

#endif /* STAGED_LOADER_REFLECT_H */
