/*
 * test_file_transfer_bof.c — get_file through the real loader.
 *
 * The C2 session is replaced by in-memory callbacks. This checks that the BOF,
 * the packed arguments, the host bridge and the loader agree: the file is
 * uploaded from the resume offset, a directory is listed instead of uploaded,
 * and the same object behaves identically as an RV32 guest.
 */

#define _POSIX_C_SOURCE 200809L

#include "bof.h"
#include "rvvm.h"

#include "test.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#ifndef BOF_LOADER_PATH
#define BOF_LOADER_PATH ""
#endif
#ifndef BOF_GET_PATH
#define BOF_GET_PATH ""
#endif
#ifndef RVVM_LOADER_PATH
#define RVVM_LOADER_PATH ""
#endif
#ifndef RV_GET_PATH
#define RV_GET_PATH ""
#endif

#define FAKE_FILES 16
#define FAKE_DATA 4096

typedef struct {
  char path[256];
  unsigned char data[FAKE_DATA];
  unsigned long len;
  int used;
} fake_file;

typedef struct {
  fake_file files[FAKE_FILES];
  unsigned char uploaded[FAKE_DATA];
  unsigned long uploaded_len;
  char upload_token[128];
  int upload_calls;
  int write_calls;
} fake_host;

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

static fake_file *find_file(fake_host *h, const char *path) {
  for (int i = 0; i < FAKE_FILES; i++) {
    if (h->files[i].used && strcmp(h->files[i].path, path) == 0)
      return &h->files[i];
  }
  return NULL;
}

static fake_file *add_file(fake_host *h, const char *path) {
  fake_file *f = find_file(h, path);
  if (f != NULL)
    return f;
  for (int i = 0; i < FAKE_FILES; i++) {
    if (h->files[i].used)
      continue;
    memset(&h->files[i], 0, sizeof(h->files[i]));
    h->files[i].used = 1;
    snprintf(h->files[i].path, sizeof(h->files[i].path), "%s", path);
    return &h->files[i];
  }
  return NULL;
}

static int fake_read(void *vctx, const char *path, uint8_t **out, size_t *len,
                     char *err, int err_cap) {
  fake_host *h = (fake_host *)vctx;
  fake_file *f = find_file(h, path);
  if (f == NULL) {
    snprintf(err, (size_t)err_cap, "no such file");
    return -1;
  }
  uint8_t *copy = (uint8_t *)malloc(f->len > 0 ? f->len : 1);
  if (copy == NULL)
    return -2;
  memcpy(copy, f->data, f->len);
  *out = copy;
  *len = f->len;
  return 0;
}

static int fake_write(void *vctx, const char *path, const uint8_t *data,
                      size_t len, char *err, int err_cap) {
  fake_host *h = (fake_host *)vctx;
  fake_file *f = add_file(h, path);
  if (f == NULL || len > sizeof(f->data)) {
    snprintf(err, (size_t)err_cap, "too many files");
    return -2;
  }
  memcpy(f->data, data, len);
  f->len = len;
  h->write_calls++;
  return 0;
}

static int fake_upload(void *vctx, const char *token, const char *path,
                       unsigned long offset, char *err, int err_cap) {
  fake_host *h = (fake_host *)vctx;
  h->upload_calls++;
  snprintf(h->upload_token, sizeof(h->upload_token), "%s", token);
  fake_file *f = find_file(h, path);
  if (f == NULL) {
    snprintf(err, (size_t)err_cap, "no such file");
    return -1;
  }
  if (offset > f->len) {
    snprintf(err, (size_t)err_cap, "offset past end of file");
    return -1;
  }
  unsigned long n = f->len - offset;
  if (n > sizeof(h->uploaded))
    return -2;
  memcpy(h->uploaded, f->data + offset, n);
  h->uploaded_len = n;
  return 0;
}

static int fake_sha256(void *vctx, const uint8_t *data, size_t len, char *hex,
                       size_t hex_cap, char *err, int err_cap) {
  (void)vctx;
  (void)data;
  (void)len;
  (void)err;
  (void)err_cap;
  if (hex == NULL || hex_cap < 65)
    return -1;
  memset(hex, '0', 64);
  hex[64] = '\0';
  return 0;
}

static char *run_entry(const uint8_t *loader, size_t loader_len,
                       const uint8_t *bof, size_t bof_len, const char *entry,
                       c2_str *args, size_t argc, fake_host *fake) {
  uint8_t packed[1024];
  size_t packed_len = 0;
  CHECK_EQ_LONG(
      c2_bof_pack_args(args, argc, packed, sizeof(packed), &packed_len), C2_OK);
  c2_bof_host host = {fake,        fake_read, fake_write, fake_upload,
                      fake_sha256, NULL,      NULL};
  char *out = NULL;
  c2_status st = c2_bof_run(loader, loader_len, bof, bof_len, entry, packed,
                            packed_len, &host, &out);
  if (st != C2_OK && out != NULL)
    fprintf(stderr, "  bof failed: %s\n", out);
  CHECK_EQ_LONG(st, C2_OK);
  return out;
}

static char *run_rv_entry(const uint8_t *loader, size_t loader_len,
                          const uint8_t *image, size_t image_len, c2_str *args,
                          size_t argc, fake_host *fake) {
  uint8_t packed[1024];
  size_t packed_len = 0;
  CHECK_EQ_LONG(
      c2_bof_pack_args(args, argc, packed, sizeof(packed), &packed_len), C2_OK);
  c2_bof_host host = {fake,        fake_read, fake_write, fake_upload,
                      fake_sha256, NULL,      NULL};
  char *out = NULL;
  CHECK_EQ_LONG(c2_rv_run(loader, loader_len, image, image_len, packed,
                          packed_len, &host, &out),
                C2_OK);
  return out;
}

static void write_text(const char *path, const char *text) {
  FILE *f = fopen(path, "wb");
  CHECK(f != NULL);
  if (f == NULL)
    return;
  CHECK_EQ_LONG(fwrite(text, 1, strlen(text), f), strlen(text));
  CHECK_EQ_LONG(fclose(f), 0);
}

int main(void) {
  if (BOF_LOADER_PATH[0] == '\0' || BOF_GET_PATH[0] == '\0') {
    printf("%s: loader/object not provided, skipped\n", __FILE__);
    TEST_DONE();
    return 0;
  }

  size_t loader_len = 0, get_len = 0;
  unsigned char *loader = slurp(BOF_LOADER_PATH, &loader_len);
  unsigned char *get_file = slurp(BOF_GET_PATH, &get_len);
  CHECK(loader != NULL && loader_len > 0);
  CHECK(get_file != NULL && get_len > 0);
  if (loader == NULL || get_file == NULL) {
    free(loader);
    free(get_file);
    TEST_DONE();
    return 0;
  }

  char tmpdir[] = "/tmp/xfer_test_XXXXXX";
  CHECK(mkdtemp(tmpdir) != NULL);
  char path_a[512], path_b[512], subdir[512], path_c[512];
  snprintf(path_a, sizeof(path_a), "%s/a.log", tmpdir);
  snprintf(path_b, sizeof(path_b), "%s/b.txt", tmpdir);
  snprintf(subdir, sizeof(subdir), "%s/sub", tmpdir);
  snprintf(path_c, sizeof(path_c), "%s/c.log", subdir);
  write_text(path_a, "alpha");
  write_text(path_b, "beta");
  CHECK_EQ_LONG(mkdir(subdir, 0700), 0);
  write_text(path_c, "gamma");

  fake_host fake;
  memset(&fake, 0, sizeof(fake));
  char *out = NULL;

  /* A file is uploaded from the resume offset; the BOF reads no bytes. */
  fake_file *src = add_file(&fake, "/tmp/source.bin");
  CHECK(src != NULL);
  memcpy(src->data, "abcdef", 6);
  src->len = 6;
  c2_str get_args[4] = {c2_str_lit("z/tmp/source.bin"), c2_str_lit("i2"),
                        c2_str_lit("ztok"), c2_str_lit("z")};
  out = run_entry(loader, loader_len, get_file, get_len, "go", get_args, 4,
                  &fake);
  CHECK(strcmp(fake.upload_token, "tok") == 0);
  CHECK_EQ_LONG(fake.uploaded_len, 4);
  CHECK(memcmp(fake.uploaded, "cdef", 4) == 0);
  CHECK(out != NULL && strstr(out, "get_file: /tmp/source.bin sent") != NULL);
  free(out);

  /* An offset past the end is refused by the agent, and no byte is sent. */
  fake.upload_calls = 0;
  fake.uploaded_len = 0;
  c2_str too_far[4] = {c2_str_lit("z/tmp/source.bin"), c2_str_lit("i10"),
                       c2_str_lit("ztok"), c2_str_lit("z")};
  out =
      run_entry(loader, loader_len, get_file, get_len, "go", too_far, 4, &fake);
  CHECK(out != NULL && strstr(out, "past") != NULL);
  CHECK_EQ_LONG(fake.uploaded_len, 0);
  free(out);

  /* A negative offset is invalid, not an unsigned resume offset. */
  fake.upload_calls = 0;
  c2_str negative[4] = {c2_str_lit("z/tmp/source.bin"), c2_str_lit("i-1"),
                        c2_str_lit("ztok"), c2_str_lit("z")};
  out = run_entry(loader, loader_len, get_file, get_len, "go", negative, 4,
                  &fake);
  CHECK(out != NULL && strstr(out, "invalid offset") != NULL);
  CHECK_EQ_LONG(fake.upload_calls, 0);
  free(out);

  /* A missing file is reported, never uploaded as an empty body. */
  fake.upload_calls = 0;
  c2_str missing[4] = {c2_str_lit("z/tmp/nope.bin"), c2_str_lit("i0"),
                       c2_str_lit("ztok"), c2_str_lit("z")};
  out =
      run_entry(loader, loader_len, get_file, get_len, "go", missing, 4, &fake);
  CHECK(out != NULL && strstr(out, "no such file") != NULL);
  CHECK_EQ_LONG(fake.uploaded_len, 0);
  free(out);

  /* A memfs key is not a disk path: no stat, straight to the upload. */
  fake_file *mem = add_file(&fake, "memfs:///payload.bin");
  CHECK(mem != NULL);
  memcpy(mem->data, "xyz", 3);
  mem->len = 3;
  c2_str mem_args[4] = {c2_str_lit("zmemfs:///payload.bin"), c2_str_lit("i1"),
                        c2_str_lit("zm"), c2_str_lit("z")};
  fake.upload_calls = 0;
  out = run_entry(loader, loader_len, get_file, get_len, "go", mem_args, 4,
                  &fake);
  CHECK(strcmp(fake.upload_token, "m") == 0);
  CHECK_EQ_LONG(fake.uploaded_len, 2);
  CHECK(memcmp(fake.uploaded, "yz", 2) == 0);
  CHECK(out != NULL && strstr(out, "memfs:///payload.bin sent") != NULL);
  free(out);

  /* A directory is listed with the filter applied; nothing is uploaded. */
  char filter[64];
  snprintf(filter, sizeof(filter), "z\\.log$");
  char dir_arg[512];
  snprintf(dir_arg, sizeof(dir_arg), "z%s", tmpdir);
  c2_str dir_args[4] = {c2_str_of(dir_arg, strlen(dir_arg)), c2_str_lit("i0"),
                        c2_str_lit("ztok"), c2_str_of(filter, strlen(filter))};
  fake.upload_calls = 0;
  out = run_entry(loader, loader_len, get_file, get_len, "go", dir_args, 4,
                  &fake);
  CHECK(out != NULL && strstr(out, path_a) != NULL);
  CHECK(out != NULL && strstr(out, path_c) != NULL);
  CHECK(out == NULL || strstr(out, path_b) == NULL);
  CHECK(out != NULL && strstr(out, "2 file(s)") != NULL);
  CHECK_EQ_LONG(fake.upload_calls, 0);
  free(out);

  /* An invalid filter is a usage error, not a crash. */
  c2_str bad_filter[4] = {c2_str_of(dir_arg, strlen(dir_arg)), c2_str_lit("i0"),
                          c2_str_lit("ztok"), c2_str_lit("z[")};
  out = run_entry(loader, loader_len, get_file, get_len, "go", bad_filter, 4,
                  &fake);
  CHECK(out != NULL && strstr(out, "invalid filter") != NULL);
  CHECK_EQ_LONG(fake.upload_calls, 0);
  free(out);

  /* The same object runs as an RV32 guest through the syscall bridge. */
  if (RVVM_LOADER_PATH[0] != '\0' && RV_GET_PATH[0] != '\0') {
    size_t rv_loader_len = 0, rv_get_len = 0;
    unsigned char *rv_loader = slurp(RVVM_LOADER_PATH, &rv_loader_len);
    unsigned char *rv_get = slurp(RV_GET_PATH, &rv_get_len);
    CHECK(rv_loader != NULL && rv_get != NULL);

    fake_host rv_fake;
    memset(&rv_fake, 0, sizeof(rv_fake));
    fake_file *rv_src = add_file(&rv_fake, "/tmp/rv-source.bin");
    CHECK(rv_src != NULL);
    memcpy(rv_src->data, "abcdef", 6);
    rv_src->len = 6;

    c2_str rv_args[4] = {c2_str_lit("z/tmp/rv-source.bin"), c2_str_lit("i3"),
                         c2_str_lit("ztok"), c2_str_lit("z")};
    out = run_rv_entry(rv_loader, rv_loader_len, rv_get, rv_get_len, rv_args, 4,
                       &rv_fake);
    CHECK(strcmp(rv_fake.upload_token, "tok") == 0);
    CHECK_EQ_LONG(rv_fake.uploaded_len, 3);
    CHECK(memcmp(rv_fake.uploaded, "def", 3) == 0);
    CHECK(out != NULL && strstr(out, "rv-source.bin sent") != NULL);
    free(out);

    /* The guest walks the same directory without a host syscall. */
    rv_fake.upload_calls = 0;
    out = run_rv_entry(rv_loader, rv_loader_len, rv_get, rv_get_len, dir_args,
                       4, &rv_fake);
    CHECK(out != NULL && strstr(out, path_a) != NULL);
    CHECK(out != NULL && strstr(out, path_c) != NULL);
    CHECK(out == NULL || strstr(out, path_b) == NULL);
    CHECK_EQ_LONG(rv_fake.upload_calls, 0);
    free(out);

    free(rv_loader);
    free(rv_get);
  }

  unlink(path_a);
  unlink(path_b);
  unlink(path_c);
  rmdir(subdir);
  rmdir(tmpdir);

  free(loader);
  free(get_file);
  TEST_DONE();
  return 0;
}
