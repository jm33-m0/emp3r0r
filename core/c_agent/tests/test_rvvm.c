/*
 * test_rvvm.c — RV32 guest execution through the rvvm module.
 *
 * The Makefile builds the real interpreter and RV32 static musl executables
 * with the shipped zig, and passes their paths in, so this exercises the
 * runtime path: in-memory mapping of the interpreter, segment loading, the
 * guest entry shim, the syscall gate, and the run limits.
 */

#include "test.h"

#include "rvvm_abi.h"
#include "util/elfload.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef RVVM_MODULE_PATH
#define RVVM_MODULE_PATH ""
#endif
#ifndef RVVM_BOF_EXEC_PATH
#define RVVM_BOF_EXEC_PATH ""
#endif
#ifndef RVVM_BOF_SPAM_EXEC_PATH
#define RVVM_BOF_SPAM_EXEC_PATH ""
#endif
#ifndef RVVM_BOF_TIME_EXEC_PATH
#define RVVM_BOF_TIME_EXEC_PATH ""
#endif
#ifndef RVVM_BOF_NET_EXEC_PATH
#define RVVM_BOF_NET_EXEC_PATH ""
#endif
#ifndef RVVM_BOF_LOCK_EXEC_PATH
#define RVVM_BOF_LOCK_EXEC_PATH ""
#endif
#ifndef RVVM_BOF_IOV_EXEC_PATH
#define RVVM_BOF_IOV_EXEC_PATH ""
#endif
#ifndef RVVM_BOF_BOUNDS_EXEC_PATH
#define RVVM_BOF_BOUNDS_EXEC_PATH ""
#endif
#ifndef RVVM_BOF_RANDOM_EXEC_PATH
#define RVVM_BOF_RANDOM_EXEC_PATH ""
#endif

typedef char *(*rv_run_fn)(const uint8_t *image, size_t image_len,
                           const struct rv_bof_args *args);
typedef const char *(*rv_last_fn)(void);
typedef int (*rv_code_fn)(void);
typedef void (*rv_free_fn)(char *);

static rv_run_fn g_run;
static rv_last_fn g_last;
static rv_code_fn g_code;
static rv_free_fn g_release;

static uint8_t *slurp(const char *path, size_t *len) {
  FILE *f = fopen(path, "rb");
  if (f == NULL)
    return NULL;
  if (fseek(f, 0, SEEK_END) != 0) {
    fclose(f);
    return NULL;
  }
  long n = ftell(f);
  if (n < 0 || fseek(f, 0, SEEK_SET) != 0) {
    fclose(f);
    return NULL;
  }
  uint8_t *b = (uint8_t *)malloc(n > 0 ? (size_t)n : 1);
  if (b == NULL) {
    fclose(f);
    return NULL;
  }
  if (n > 0 && fread(b, 1, (size_t)n, f) != (size_t)n) {
    free(b);
    fclose(f);
    return NULL;
  }
  fclose(f);
  *len = (size_t)n;
  return b;
}

static uint32_t rd32(const uint8_t *p) {
  return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) |
         ((uint32_t)p[3] << 24);
}

static void wr32(uint8_t *p, uint32_t v) {
  p[0] = (uint8_t)v;
  p[1] = (uint8_t)(v >> 8);
  p[2] = (uint8_t)(v >> 16);
  p[3] = (uint8_t)(v >> 24);
}

static int open_module(void) {
  size_t len = 0;
  uint8_t *img = slurp(RVVM_MODULE_PATH, &len);
  if (img == NULL) {
    fprintf(stderr, "cannot read %s\n", RVVM_MODULE_PATH);
    return -1;
  }
  char err[160];
  elfload_module *mod = elfload_map(img, len, err, sizeof(err));
  free(img);
  if (mod == NULL) {
    fprintf(stderr, "map %s: %s\n", RVVM_MODULE_PATH, err);
    return -1;
  }
  g_run = (rv_run_fn)elfload_sym(mod, "Run");
  g_last = (rv_last_fn)elfload_sym(mod, "LastError");
  g_code = (rv_code_fn)elfload_sym(mod, "ExitCode");
  g_release = (rv_free_fn)elfload_sym(mod, "Free");
  if (g_run == NULL || g_last == NULL || g_code == NULL || g_release == NULL) {
    fprintf(stderr, "module is missing its exports\n");
    return -1;
  }
  return 0;
}

static char *bof_run(const uint8_t *img, size_t len, const uint8_t *args,
                     size_t args_len) {
  static const uint8_t env[] = "PATH=/usr/bin:/bin";
  struct rv_bof_args a;
  a.buf = args;
  a.len = args_len;
  a.env = env;
  a.env_len = sizeof(env);
  return g_run(img, len, &a);
}

int main(void) {
  if (open_module() != 0)
    return 1;

  /* Packed arguments: u32 body length | u32 string length | "alpha\0". */
  static const uint8_t packed[] = {0x0a, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00,
                                   0x00, 'a',  'l',  'p',  'h',  'a',  0x00};
  size_t exec_len = 0;
  uint8_t *exec_img = slurp(RVVM_BOF_EXEC_PATH, &exec_len);
  CHECK(exec_img != NULL);
  if (exec_img == NULL)
    return 1;

  char *out = bof_run(exec_img, exec_len, packed, sizeof(packed));
  CHECK(out != NULL);
  CHECK(out != NULL && strcmp(out, "bof alpha (6)\n") == 0);
  CHECK_EQ_LONG(g_code(), 0);
  g_release(out);

  /* No arguments: the guest still runs and sees an empty parser. */
  out = bof_run(exec_img, exec_len, NULL, 0);
  CHECK(out != NULL);
  CHECK(out != NULL && strcmp(out, "bof none\n") == 0);
  g_release(out);

  /* Malformed executables are rejected before any guest instruction runs. */
  uint8_t *bad = (uint8_t *)malloc(exec_len);
  CHECK(bad != NULL);
  if (bad != NULL) {
#define BAD_COPY()                                                             \
  do {                                                                         \
    memcpy(bad, exec_img, exec_len);                                           \
  } while (0)
#define EXPECT_ERR(buf, n, needle)                                             \
  do {                                                                         \
    out = bof_run((buf), (n), NULL, 0);                                        \
    CHECK(out == NULL);                                                        \
    CHECK(strstr(g_last(), (needle)) != NULL);                                 \
  } while (0)

    out = bof_run(NULL, 0, NULL, 0);
    CHECK(out == NULL);
    CHECK(strstr(g_last(), "empty image") != NULL);

    BAD_COPY();
    EXPECT_ERR(bad, 8, "image too small");
    BAD_COPY();
    bad[0] = 0; /* not ELF */
    EXPECT_ERR(bad, exec_len, "not an ELF image");
    BAD_COPY();
    bad[4] = 2; /* ELFCLASS64 */
    EXPECT_ERR(bad, exec_len, "ELF32");
    BAD_COPY();
    bad[16] = 1; /* ET_REL */
    bad[17] = 0;
    EXPECT_ERR(bad, exec_len, "not an executable image");
    BAD_COPY();
    bad[18] = 0; /* e_machine = 0 */
    bad[19] = 0;
    EXPECT_ERR(bad, exec_len, "unsupported guest image");
    BAD_COPY();
    wr32(bad + 24, 0); /* e_entry */
    EXPECT_ERR(bad, exec_len, "bad executable entry point");
    BAD_COPY();
    bad[44] = 0; /* e_phnum */
    bad[45] = 0;
    EXPECT_ERR(bad, exec_len, "bad program headers");
    BAD_COPY();
    wr32(bad + 28, 0x7fffffffu); /* e_phoff */
    EXPECT_ERR(bad, exec_len, "bad program headers");

    BAD_COPY();
    uint32_t phoff = rd32(bad + 28);
    uint16_t phent = (uint16_t)(bad[42] | (bad[43] << 8));
    uint16_t phnum = (uint16_t)(bad[44] | (bad[45] << 8));
    int patched = 0;
    for (uint16_t i = 0; i < phnum && !patched; i++) {
      uint8_t *ph = bad + phoff + (size_t)i * phent;
      if (rd32(ph) == 1) {        /* PT_LOAD */
        wr32(ph + 8, 0x90000000); /* p_vaddr outside guest RAM */
        patched = 1;
      }
    }
    CHECK(patched == 1);
    EXPECT_ERR(bad, exec_len, "bad executable segment");
    free(bad);
  }

  /* Argument blocks larger than the module limit are rejected. */
  {
    size_t big_len = (2u << 20) + 1;
    uint8_t *big = (uint8_t *)malloc(big_len);
    CHECK(big != NULL);
    if (big != NULL) {
      memset(big, 0, big_len);
      out = bof_run(exec_img, exec_len, big, big_len);
      CHECK(out == NULL);
      CHECK(strstr(g_last(), "bad argument block") != NULL);
      free(big);
    }
  }

  /* The guest clock reaches the host through the syscall gate. */
  {
    size_t time_len = 0;
    uint8_t *time_img = slurp(RVVM_BOF_TIME_EXEC_PATH, &time_len);
    CHECK(time_img != NULL);
    if (time_img != NULL) {
      out = bof_run(time_img, time_len, NULL, 0);
      CHECK(out != NULL);
      CHECK_EQ_LONG(g_code(), 0);
      g_release(out);
      free(time_img);
    }
  }

  /* Socket syscalls, including recvfrom's in/out address length. */
  {
    size_t net_len = 0;
    uint8_t *net_img = slurp(RVVM_BOF_NET_EXEC_PATH, &net_len);
    CHECK(net_img != NULL);
    if (net_img != NULL) {
      out = bof_run(net_img, net_len, NULL, 0);
      CHECK(out != NULL);
      CHECK_EQ_LONG(g_code(), 0);
      g_release(out);
      free(net_img);
    }
  }

  /* fcntl lock commands translate a guest struct flock. */
  {
    size_t lock_len = 0;
    uint8_t *lock_img = slurp(RVVM_BOF_LOCK_EXEC_PATH, &lock_len);
    CHECK(lock_img != NULL);
    if (lock_img != NULL) {
      out = bof_run(lock_img, lock_len, NULL, 0);
      CHECK(out != NULL);
      CHECK_EQ_LONG(g_code(), 0);
      g_release(out);
      free(lock_img);
    }
  }

  /* Zero-length iovecs carry no address and must not fail readv or writev;
   * libc passes one with a NULL base on buffered stdio calls. */
  {
    size_t iov_len = 0;
    uint8_t *iov_img = slurp(RVVM_BOF_IOV_EXEC_PATH, &iov_len);
    CHECK(iov_img != NULL);
    if (iov_img != NULL) {
      out = bof_run(iov_img, iov_len, NULL, 0);
      CHECK(out != NULL);
      CHECK(out != NULL && strcmp(out, "iov") == 0);
      CHECK_EQ_LONG(g_code(), 0);
      g_release(out);
      free(iov_img);
    }
  }

  /* The gate rejects untranslatable pointers and marks guest descriptors
   * close-on-exec. */
  {
    size_t bounds_len = 0;
    uint8_t *bounds_img = slurp(RVVM_BOF_BOUNDS_EXEC_PATH, &bounds_len);
    CHECK(bounds_img != NULL);
    if (bounds_img != NULL) {
      out = bof_run(bounds_img, bounds_len, NULL, 0);
      CHECK(out != NULL);
      CHECK_EQ_LONG(g_code(), 0);
      g_release(out);
      free(bounds_img);
    }
  }

  /* AT_RANDOM must be fresh for every run, not a build-time pattern. */
  {
    size_t random_len = 0;
    uint8_t *random_img = slurp(RVVM_BOF_RANDOM_EXEC_PATH, &random_len);
    CHECK(random_img != NULL);
    if (random_img != NULL) {
      char *first = bof_run(random_img, random_len, NULL, 0);
      CHECK(first != NULL);
      if (first != NULL) {
        size_t n = strlen(first);
        char *saved = (char *)malloc(n + 1);
        CHECK(saved != NULL);
        if (saved != NULL)
          memcpy(saved, first, n + 1);
        g_release(first);
        out = bof_run(random_img, random_len, NULL, 0);
        CHECK(out != NULL);
        CHECK(saved != NULL && out != NULL && strcmp(saved, out) != 0);
        CHECK_EQ_LONG(g_code(), 0);
        free(saved);
        g_release(out);
      }
      free(random_img);
    }
  }

  /* Output is capped so a BOF cannot grow the result buffer without bound. */
  {
    size_t spam_len = 0;
    uint8_t *spam = slurp(RVVM_BOF_SPAM_EXEC_PATH, &spam_len);
    CHECK(spam != NULL);
    if (spam != NULL) {
      out = bof_run(spam, spam_len, NULL, 0);
      CHECK(out == NULL);
      CHECK(strstr(g_last(), "output limit reached") != NULL);
      free(spam);
    }
  }

  free(exec_img);
  TEST_DONE();
}
