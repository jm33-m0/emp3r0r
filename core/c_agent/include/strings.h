#ifndef C2_STRINGS_H
#define C2_STRINGS_H

/*
 * strings.h — freestanding libc string/memory replacements.
 *
 * A -nostdlib payload (raw shellcode, downloader blob, unpacker) has no libc,
 * but the compiler still emits calls to memcpy/memset/strlen/strcmp and the
 * code here needs strstr. These definitions are linked only into freestanding
 * artifacts: a hosted agent gets them from libc and must NOT link strings.c
 * (overriding libc symbols in a hosted process is unsafe).
 *
 * The prototypes match the C standard exactly so a translation unit that also
 * includes <string.h> sees a compatible redeclaration.
 */

#include <stddef.h>

void *memcpy(void *dest, const void *src, size_t n);
void *memset(void *s, int c, size_t n);
size_t strlen(const char *s);
int strcmp(const char *s1, const char *s2);
char *strstr(const char *haystack, const char *needle);

#endif /* C2_STRINGS_H */
