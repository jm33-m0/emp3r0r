/*
 * test_elfload.c — in-memory ELF loader.
 *
 * The Makefile builds the real coffloader_linux.so and passes its path in, so
 * the loader maps and relocates the actual dependency. The point of the test is
 * twofold: the exports resolve, and mapping the image creates no file
 * descriptor (the loader must never touch an fd or disk).
 */

#include "util/elfload.h"

#include "test.h"

#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef BOF_LOADER_PATH
#define BOF_LOADER_PATH ""
#endif

#ifndef FAULTY_CTOR_PATH
#define FAULTY_CTOR_PATH ""
#endif

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
    fclose(f);
    free(b);
    return NULL;
  }
  fclose(f);
  *len = (size_t)n;
  return b;
}

/* Count entries under /proc/self/fd; the opendir fd is closed before we
 * return, so equal counts across a call mean no descriptor leaked. */
static int count_fds(void) {
  DIR *d = opendir("/proc/self/fd");
  if (d == NULL)
    return -1;
  int n = 0;
  struct dirent *e;
  while ((e = readdir(d)) != NULL) {
    if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0)
      continue;
    n++;
  }
  closedir(d);
  return n;
}

static void test_reject(void) {
  uint8_t buf[64];
  memset(buf, 0, sizeof(buf));

  CHECK(elfload_map(NULL, 0, NULL, 0) == NULL);
  CHECK(elfload_map(buf, 0, NULL, 0) == NULL);
  CHECK(elfload_map(buf, sizeof(buf), NULL, 0) == NULL); /* bad magic */

  /* Valid ELF64 header with a zero program-header count must still fail. */
  buf[0] = 0x7f;
  buf[1] = 'E';
  buf[2] = 'L';
  buf[3] = 'F';
  buf[4] = 2; /* ELFCLASS64 */
  buf[5] = 1; /* ELFDATA2LSB */
  buf[6] = 1; /* EV_CURRENT */
  buf[16] = 3; /* ET_DYN */
  buf[18] = 62; /* EM_X86_64 */
  CHECK(elfload_map(buf, sizeof(buf), NULL, 0) == NULL);

  /* The error buffer is populated for a rejected image. */
  char err[64];
  err[0] = 'x';
  CHECK(elfload_map(buf, sizeof(buf), err, sizeof(err)) == NULL);
  CHECK(err[0] != '\0' && err[0] != 'x');
}

/* A valid image whose constructor faults must be rejected by the crash guard
 * without taking the test process down. */
static void test_faulty_ctor(void) {
  if (FAULTY_CTOR_PATH[0] == '\0')
    return;
  size_t len = 0;
  uint8_t *image = slurp(FAULTY_CTOR_PATH, &len);
  CHECK(image != NULL && len > 0);
  if (image == NULL)
    return;
  char err[160];
  elfload_module *m = elfload_map(image, len, err, sizeof(err));
  CHECK(m == NULL);
  CHECK(strcmp(err, "constructor crashed") == 0);
  free(image);
}

int main(void) {
  test_reject();
  test_faulty_ctor();

  if (BOF_LOADER_PATH[0] == '\0') {
    printf("%s: loader not provided, skipped runtime part\n", __FILE__);
    TEST_DONE();
    return 0;
  }

  size_t len = 0;
  uint8_t *image = slurp(BOF_LOADER_PATH, &len);
  CHECK(image != NULL && len > 0);
  if (image == NULL) {
    TEST_DONE();
    return 0;
  }

  int before = count_fds();
  CHECK(before >= 0);

  char err[160];

  /* Regression: a PT_LOAD with no access flags used to be mprotected
   * PROT_NONE; when it covered the image (ELF header included) every later
   * symbol lookup read unmapped memory. Patch the real image's first PT_LOAD
   * and require rejection. */
  {
    uint8_t *bad = (uint8_t *)malloc(len);
    CHECK(bad != NULL);
    if (bad != NULL) {
      memcpy(bad, image, len);
      uint64_t phoff = 0;
      uint16_t phentsize = 0, phnum = 0;
      memcpy(&phoff, bad + 32, sizeof(phoff));
      memcpy(&phentsize, bad + 54, sizeof(phentsize));
      memcpy(&phnum, bad + 56, sizeof(phnum));
      int patched = 0;
      for (uint16_t i = 0; i < phnum &&
                           phoff + (uint64_t)phentsize * (i + 1) <= len;
           i++) {
        uint8_t *p = bad + phoff + (size_t)i * phentsize;
        uint32_t type = 0;
        memcpy(&type, p, sizeof(type));
        if (type == 1 /* PT_LOAD */) {
          memset(p + 4, 0, 4); /* p_flags = 0 */
          patched = 1;
          break;
        }
      }
      CHECK(patched);
      CHECK(elfload_map(bad, len, err, sizeof(err)) == NULL);
      free(bad);
    }
  }

  elfload_module *m = elfload_map(image, len, err, sizeof(err));
  CHECK(m != NULL);
  if (m != NULL) {
    CHECK(elfload_sym(m, "bof_run") != NULL);
    CHECK(elfload_sym(m, "bof_last_error") != NULL);
    CHECK(elfload_sym(m, "bof_free") != NULL);
    CHECK(elfload_sym(m, "definitely_not_exported") == NULL);
    CHECK(elfload_sym(m, NULL) == NULL);
  }
  /* Mapping the image must not hold an fd open. */
  CHECK_EQ_LONG(count_fds(), before);

  elfload_free(m);
  CHECK_EQ_LONG(count_fds(), before);
  free(image);

  TEST_DONE();
}
