#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>

#include "elf.h"

void __attribute__((constructor)) initLibrary(void)
{
    FILE* f = fopen("emp3r0r", "rb");

    fseek(f, 0, SEEK_END);
    int size = ftell(f);

    fseek(f, 0L, SEEK_SET);

    char* buf = malloc(size);
    fread(buf, size, 1, f);

    /* printf("main: %p\n", elf_sym(buf, "main")); */

    // Run the ELF
    elf_run(buf, NULL, NULL);
}

void __attribute__((destructor)) cleanUpLibrary(void) { }
