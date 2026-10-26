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
#include <string.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <unistd.h>

typedef int (*mask_fn)(unsigned seconds, uintptr_t probe);

volatile unsigned char g_canary[64] __attribute__((aligned(64))) = {
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
    0xcc, 0xdd, 0xee, 0xff, 0x10, 0x21, 0x32, 0x43, 0x54, 0x65, 0x76, 0x87,
    0x98, 0xa9, 0xba, 0xcb, 0xdc, 0xed, 0xfe, 0x0f, 0x5a, 0x5a, 0x5a, 0x5a,
    0xa5, 0xa5, 0xa5, 0xa5, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14,
    0x15, 0x16, 0x17, 0x18};

static int read_mem(int fd, uintptr_t addr, void *buf, size_t len) {
  size_t off = 0;
  while (off < len) {
    ssize_t n = pread(fd, (unsigned char *)buf + off, len - off,
                      (off_t)(addr + off));
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
  mask_fn mask = (mask_fn)dlsym(lib, "stager_mask_provider_sleep");
  if (mask == NULL) {
    fprintf(stderr, "dlsym: %s\n", dlerror());
    return 2;
  }

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
    unsigned char before[sizeof(g_canary)];
    unsigned char during[sizeof(g_canary)];
    unsigned char after[sizeof(g_canary)];
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

  int rc = mask(2, (uintptr_t)(void *)&main);
  int status = 0;
  waitpid(child, &status, 0);

  int ok = rc == 0 && WIFEXITED(status) && WEXITSTATUS(status) == 0;
  printf("mask rc=%d child=%d %s\n", rc,
         WIFEXITED(status) ? WEXITSTATUS(status) : -1, ok ? "ok" : "FAIL");
  return ok ? 0 : 1;
}
