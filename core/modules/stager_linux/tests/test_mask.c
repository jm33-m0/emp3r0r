/*
 * test_mask.c — hosted exercise of the stager mask stub.
 *
 * The mask code is built as a shared object, so it lives in a different mapping
 * from the test executable it masks. A forked child snapshots the parent's
 * canary before the mask, reads it again while the parent sleeps, and once more
 * after the mask returns. The child is outside the masked address space, so it
 * can observe all three states.
 */

#define _GNU_SOURCE
#include <dlfcn.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <unistd.h>

typedef int (*mask_fn)(unsigned seconds, uintptr_t probe, void *stack_top,
                       uintptr_t keep_start, uintptr_t keep_end);

#define CANARY_SIZE 64u
#define STACK_SIZE (64u * 1024u)

static volatile unsigned char *g_canary;

static int read_mem(int fd, uintptr_t addr, void *buf, size_t len) {
  size_t off = 0;
  while (off < len) {
    ssize_t n =
        pread(fd, (unsigned char *)buf + off, len - off, (off_t)(addr + off));
    if (n <= 0)
      return -1;
    off += (size_t)n;
  }
  return 0;
}

int main(void) {
  void *lib = dlopen("./tests/libmask_test.so", RTLD_NOW | RTLD_LOCAL);
  if (lib == NULL) {
    fprintf(stderr, "dlopen: %s\n", dlerror());
    return 2;
  }
  mask_fn mask = (mask_fn)dlsym(lib, "stager_mask_run_on_stack");
  if (mask == NULL) {
    fprintf(stderr, "dlsym: %s\n", dlerror());
    return 2;
  }
  /* The canary lives on the process heap, which the provider masks. */
  g_canary = malloc(CANARY_SIZE);
  if (g_canary == NULL) {
    fprintf(stderr, "malloc: %m\n");
    return 2;
  }
  void *stack = mmap(NULL, STACK_SIZE, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (stack == MAP_FAILED) {
    fprintf(stderr, "mmap: %m\n");
    return 2;
  }
  for (uintptr_t i = 0; i < CANARY_SIZE; i++)
    g_canary[i] = (unsigned char)(0x11u * (unsigned)i + 0x5au);

  int go[2], ready[2];
  if (pipe(go) != 0 || pipe(ready) != 0)
    return 2;

  pid_t child = fork();
  if (child == 0) {
    close(go[1]);
    close(ready[0]);
    char c;
    if (read(go[0], &c, 1) != 1)
      _exit(2);
    close(go[0]);

    pid_t parent = getppid();
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/mem", (int)parent);
    int fd = open(path, O_RDONLY);
    if (fd < 0)
      _exit(3);

    uintptr_t addr = (uintptr_t)(void *)g_canary;
    unsigned char before[CANARY_SIZE];
    unsigned char during[CANARY_SIZE];
    unsigned char after[CANARY_SIZE];
    if (read_mem(fd, addr, before, sizeof(before)) != 0)
      _exit(4);
    if (write(ready[1], "R", 1) != 1)
      _exit(5);
    close(ready[1]);

    usleep(400000);
    if (read_mem(fd, addr, during, sizeof(during)) != 0)
      _exit(6);
    usleep(3000000);
    if (read_mem(fd, addr, after, sizeof(after)) != 0)
      _exit(7);
    close(fd);

    int changed = memcmp(before, during, sizeof(before)) != 0;
    int restored = memcmp(before, after, sizeof(before)) == 0;
    _exit(changed && restored ? 0 : 8);
  }

  close(go[0]);
  close(ready[1]);
  if (prctl(PR_SET_PTRACER, (unsigned long)child, 0, 0, 0) != 0) {
    /* Yama may be disabled; the test still works when /proc/<pid>/mem is open. */
  }
  if (write(go[1], "G", 1) != 1)
    return 2;
  close(go[1]);
  char ack;
  if (read(ready[0], &ack, 1) != 1)
    return 2;
  close(ready[0]);

  uintptr_t keep_start = (uintptr_t)stack;
  uintptr_t keep_end = keep_start + STACK_SIZE;
  int rc = mask(2, (uintptr_t)(void *)main, (void *)(keep_end & ~(uintptr_t)15),
                keep_start, keep_end);
  int status = 0;
  waitpid(child, &status, 0);

  int ok = rc == 0 && WIFEXITED(status) && WEXITSTATUS(status) == 0;
  printf("mask rc=%d child=%d %s\n", rc,
         WIFEXITED(status) ? WEXITSTATUS(status) : -1, ok ? "ok" : "FAIL");
  return ok ? 0 : 1;
}
