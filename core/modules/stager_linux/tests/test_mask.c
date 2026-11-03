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
#include <pthread.h>
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

/* A whole ELF file image in writable anonymous memory, the shape a loader's
 * decompression buffer has. The provider masks it like any other anonymous
 * image: leaving it readable would expose the payload for the whole sleep. */
static void *g_file_copy;

/* A writable anonymous mapping whose base holds an ELF header but only part of
 * a file image, standing in for an image whose header page is writable. It has
 * to be masked too, not skipped because it is writable. */
static void *g_live_header;

/* Copy a shared object into anonymous writable memory so the process holds a
 * complete ELF file image, the way a loader's decompression buffer does. The
 * wrapped payload is always a shared object (ET_DYN), which is what a live
 * in-memory image can also be, so this is the shape the provider has to
 * recognise. */
static int build_file_copy(void) {
  int fd = open("./tests/libmask_test.so", O_RDONLY);
  if (fd < 0)
    return -1;
  off_t size = lseek(fd, 0, SEEK_END);
  if (size <= 0 || lseek(fd, 0, SEEK_SET) != 0) {
    close(fd);
    return -1;
  }
  size_t len = ((size_t)size + 4095u) & ~(size_t)4095u;
  size_t span = len + 2u * 4096u;
  void *raw = mmap(NULL, span, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (raw == MAP_FAILED) {
    close(fd);
    return -1;
  }
  /* The first page is left unreadable so the kernel cannot merge the copy with
   * the neighbouring mappings into one VMA: the ELF header has to stay at the
   * base of the mapping for the provider to see it. */
  if (mprotect(raw, 4096u, PROT_NONE) != 0 ||
      mprotect((unsigned char *)raw + 4096u + len, 4096u, PROT_NONE) != 0) {
    close(fd);
    munmap(raw, span);
    return -1;
  }
  unsigned char *map = (unsigned char *)raw + 4096u;
  size_t off = 0;
  while (off < (size_t)size) {
    ssize_t n = pread(fd, map + off, (size_t)size - off, (off_t)off);
    if (n <= 0) {
      close(fd);
      munmap(raw, span);
      return -1;
    }
    off += (size_t)n;
  }
  close(fd);
  g_file_copy = map;
  return 0;
}

/* A writable mapping that starts with an ELF header but holds only part of the
 * file image: the section header table the header points at lies past the end
 * of the mapping, the way it does for a live image. */
static int build_live_header(void) {
  if (g_file_copy == NULL)
    return -1;
  size_t len = 2u * 4096u;
  void *map = mmap(NULL, len + 2u * 4096u, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (map == MAP_FAILED)
    return -1;
  if (mprotect(map, 4096u, PROT_NONE) != 0 ||
      mprotect((unsigned char *)map + 4096u + len, 4096u, PROT_NONE) != 0) {
    munmap(map, len + 2u * 4096u);
    return -1;
  }
  unsigned char *p = (unsigned char *)map + 4096u;
  memcpy(p, g_file_copy, len);
  g_live_header = p;
  return 0;
}

/* glibc keeps joined thread stacks mapped, and a stack's guard page can be
 * merged into the reported VMA while staying unreadable. Range discovery must
 * not fault reading such a mapping's base. */
static void *touch_stack(void *arg) {
  volatile unsigned char buf[16u * 1024u];
  for (size_t i = 0; i < sizeof(buf); i++)
    buf[i] = (unsigned char)((uintptr_t)arg + i);
  return NULL;
}

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

  if (build_file_copy() != 0 || build_live_header() != 0) {
    fprintf(stderr, "build ELF mappings: %m\n");
    return 2;
  }

  /* Fill and join threads so glibc caches their stacks. The cache keeps each
   * guard page unreadable while /proc/self/maps can merge the stacks into one
   * readable-looking VMA. */
  pthread_t threads[3];
  for (size_t i = 0; i < 3; i++)
    if (pthread_create(&threads[i], NULL, touch_stack, (void *)(uintptr_t)i) !=
        0)
      return 2;
  for (size_t i = 0; i < 3; i++)
    (void)pthread_join(threads[i], NULL);

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

    /* Both ELF mappings must be readable while the agent runs, so the child can
     * sample them before, during and after the mask. */
    unsigned char copy_page[64];
    unsigned char header_page[64];
    if (read_mem(fd, (uintptr_t)g_file_copy, copy_page, sizeof(copy_page)) != 0)
      _exit(9);
    if (read_mem(fd, (uintptr_t)g_live_header, header_page,
                 sizeof(header_page)) != 0)
      _exit(9);
    if (write(ready[1], "R", 1) != 1)
      _exit(5);
    close(ready[1]);

    usleep(400000);
    if (read_mem(fd, addr, during, sizeof(during)) != 0)
      _exit(6);
    unsigned char copy_during[64];
    if (read_mem(fd, (uintptr_t)g_file_copy, copy_during,
                 sizeof(copy_during)) != 0)
      _exit(12);
    unsigned char header_during[64];
    if (read_mem(fd, (uintptr_t)g_live_header, header_during,
                 sizeof(header_during)) != 0)
      _exit(10);
    usleep(3000000);
    if (read_mem(fd, addr, after, sizeof(after)) != 0)
      _exit(7);
    unsigned char copy_after[64];
    if (read_mem(fd, (uintptr_t)g_file_copy, copy_after, sizeof(copy_after)) !=
        0)
      _exit(13);
    unsigned char header_after[64];
    if (read_mem(fd, (uintptr_t)g_live_header, header_after,
                 sizeof(header_after)) != 0)
      _exit(11);
    close(fd);

    int changed = memcmp(before, during, sizeof(before)) != 0;
    int restored = memcmp(before, after, sizeof(before)) == 0;
    int copy_masked = memcmp(copy_page, copy_during, sizeof(copy_page)) != 0;
    int copy_restored = memcmp(copy_page, copy_after, sizeof(copy_page)) == 0;
    int header_masked =
        memcmp(header_page, header_during, sizeof(header_page)) != 0;
    int header_restored =
        memcmp(header_page, header_after, sizeof(header_page)) == 0;
    _exit(changed && restored && copy_masked && copy_restored &&
                  header_masked && header_restored
              ? 0
              : 8);
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
