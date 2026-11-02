/*
 * test_exec_bof.c — the exec BOF through the real loaders.
 *
 * The BOF parses the command, calls ExecCmd and prints what the host returns.
 * This checks that contract against a recording callback, as a native object
 * and as an RV32 guest through the syscall gate.
 */

#define _POSIX_C_SOURCE 200809L

#include "bof.h"
#include "rvvm.h"

#include "test.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef BOF_LOADER_PATH
#define BOF_LOADER_PATH ""
#endif
#ifndef BOF_EXEC_PATH
#define BOF_EXEC_PATH ""
#endif
#ifndef RVVM_LOADER_PATH
#define RVVM_LOADER_PATH ""
#endif
#ifndef RV_EXEC_PATH
#define RV_EXEC_PATH ""
#endif

typedef struct {
  char cmd[256];
  int calls;
  int shell; /* last shell flag the BOF passed */
  const char *output;
  int fail;     /* non-zero returns a negative status with an error */
  int truncate; /* non-zero fills the buffer to force the BOF's notice */
} fake_host;

static int fake_exec(void *vctx, const char *cmd, int shell, char *out,
                     size_t out_cap, char *err, int err_cap) {
  fake_host *h = (fake_host *)vctx;
  h->calls++;
  h->shell = shell;
  snprintf(h->cmd, sizeof(h->cmd), "%s", cmd != NULL ? cmd : "");
  if (h->fail) {
    if (err != NULL && err_cap > 0)
      snprintf(err, (size_t)err_cap, "spawn denied");
    return -1;
  }
  if (h->truncate) {
    size_t n = out_cap - 1;
    memset(out, 'A', n);
    out[n] = '\0';
    return (int)n;
  }
  size_t n = h->output != NULL ? strlen(h->output) : 0;
  if (n >= out_cap)
    n = out_cap - 1;
  memcpy(out, h->output, n);
  out[n] = '\0';
  return (int)n;
}

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

static char *run_entry(const uint8_t *loader, size_t loader_len,
                       const uint8_t *bof, size_t bof_len, c2_str *args,
                       size_t argc, fake_host *fake) {
  uint8_t packed[1024];
  size_t packed_len = 0;
  CHECK_EQ_LONG(
      c2_bof_pack_args(args, argc, packed, sizeof(packed), &packed_len), C2_OK);
  c2_bof_host host = {fake, NULL, NULL, NULL, NULL, NULL, fake_exec};
  char *out = NULL;
  c2_status st = c2_bof_run(loader, loader_len, bof, bof_len, "go", packed,
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
  c2_bof_host host = {fake, NULL, NULL, NULL, NULL, NULL, fake_exec};
  char *out = NULL;
  c2_status st = c2_rv_run(loader, loader_len, image, image_len, packed,
                           packed_len, &host, &out);
  if (st != C2_OK && out != NULL)
    fprintf(stderr, "  rv failed: %s\n", out);
  CHECK_EQ_LONG(st, C2_OK);
  return out;
}

int main(void) {
  if (BOF_LOADER_PATH[0] == '\0' || BOF_EXEC_PATH[0] == '\0') {
    printf("%s: loader/object not provided, skipped\n", __FILE__);
    TEST_DONE();
    return 0;
  }

  size_t loader_len = 0, exec_len = 0;
  unsigned char *loader = slurp(BOF_LOADER_PATH, &loader_len);
  unsigned char *exec = slurp(BOF_EXEC_PATH, &exec_len);
  CHECK(loader != NULL && loader_len > 0);
  CHECK(exec != NULL && exec_len > 0);
  if (loader == NULL || exec == NULL) {
    free(loader);
    free(exec);
    TEST_DONE();
    return 0;
  }

  fake_host fake;
  memset(&fake, 0, sizeof(fake));
  fake.output = "uid=42(user)\nmarker\n";
  char *out = NULL;

  /* The command reaches the host verbatim and its output comes back. */
  c2_str args[1] = {c2_str_lit("zecho marker")};
  out = run_entry(loader, loader_len, exec, exec_len, args, 1, &fake);
  CHECK_EQ_LONG(fake.calls, 1);
  CHECK(strcmp(fake.cmd, "echo marker") == 0);
  CHECK(out != NULL && strstr(out, "uid=42(user)\nmarker\n") != NULL);
  free(out);

  /* A refused spawn reports the host's error, not a success. */
  memset(&fake, 0, sizeof(fake));
  fake.fail = 1;
  out = run_entry(loader, loader_len, exec, exec_len, args, 1, &fake);
  CHECK_EQ_LONG(fake.calls, 1);
  CHECK(out != NULL && strstr(out, "exec: spawn denied") != NULL);
  free(out);

  /* A full buffer is announced instead of silently cutting the output. */
  memset(&fake, 0, sizeof(fake));
  fake.truncate = 1;
  out = run_entry(loader, loader_len, exec, exec_len, args, 1, &fake);
  CHECK_EQ_LONG(fake.calls, 1);
  CHECK(out != NULL &&
        strstr(out, "exec: output truncated at 65535 bytes") != NULL);
  free(out);

  /* The mode argument selects the execution model: "exec" asks for a direct
   * exec without a shell, "shell" (the default) for /bin/sh -c. */
  memset(&fake, 0, sizeof(fake));
  fake.output = "direct\n";
  c2_str direct[2] = {c2_str_lit("zecho direct"), c2_str_lit("zexec")};
  out = run_entry(loader, loader_len, exec, exec_len, direct, 2, &fake);
  CHECK_EQ_LONG(fake.calls, 1);
  CHECK_EQ_LONG(fake.shell, 0);
  CHECK(strcmp(fake.cmd, "echo direct") == 0);
  free(out);

  memset(&fake, 0, sizeof(fake));
  fake.output = "shell\n";
  c2_str shell_args[2] = {c2_str_lit("zecho shell"), c2_str_lit("zshell")};
  out = run_entry(loader, loader_len, exec, exec_len, shell_args, 2, &fake);
  CHECK_EQ_LONG(fake.calls, 1);
  CHECK_EQ_LONG(fake.shell, 1);
  free(out);

  /* An unknown mode is rejected before the host is asked to run anything. */
  memset(&fake, 0, sizeof(fake));
  c2_str bad_mode[2] = {c2_str_lit("zecho shell"), c2_str_lit("zbogus")};
  out = run_entry(loader, loader_len, exec, exec_len, bad_mode, 2, &fake);
  CHECK_EQ_LONG(fake.calls, 0);
  CHECK(out != NULL && strstr(out, "exec: invalid mode bogus") != NULL);
  free(out);

  /* An empty command never reaches the host. */
  memset(&fake, 0, sizeof(fake));
  c2_str empty[1] = {c2_str_lit("z")};
  out = run_entry(loader, loader_len, exec, exec_len, empty, 1, &fake);
  CHECK_EQ_LONG(fake.calls, 0);
  CHECK(out != NULL && strstr(out, "exec: missing command") != NULL);
  free(out);

  free(loader);
  free(exec);

  /* The same object runs as an RV32 guest: the command and its output cross
   * the syscall gate, and the guest has no error channel to show. */
  if (RVVM_LOADER_PATH[0] != '\0' && RV_EXEC_PATH[0] != '\0') {
    size_t rv_loader_len = 0, rv_exec_len = 0;
    unsigned char *rv_loader = slurp(RVVM_LOADER_PATH, &rv_loader_len);
    unsigned char *rv_exec = slurp(RV_EXEC_PATH, &rv_exec_len);
    CHECK(rv_loader != NULL && rv_loader_len > 0);
    CHECK(rv_exec != NULL && rv_exec_len > 0);
    if (rv_loader != NULL && rv_exec != NULL) {
      fake_host rv_fake;
      memset(&rv_fake, 0, sizeof(rv_fake));
      rv_fake.output = "rv-output\n";
      c2_str rv_args[1] = {c2_str_lit("zid -u")};
      out = run_rv_entry(rv_loader, rv_loader_len, rv_exec, rv_exec_len,
                         rv_args, 1, &rv_fake);
      CHECK_EQ_LONG(rv_fake.calls, 1);
      CHECK(strcmp(rv_fake.cmd, "id -u") == 0);
      CHECK(out != NULL && strstr(out, "rv-output\n") != NULL);
      free(out);

      memset(&rv_fake, 0, sizeof(rv_fake));
      rv_fake.output = "rv-direct\n";
      c2_str rv_direct[2] = {c2_str_lit("zid -u"), c2_str_lit("zexec")};
      out = run_rv_entry(rv_loader, rv_loader_len, rv_exec, rv_exec_len,
                         rv_direct, 2, &rv_fake);
      CHECK_EQ_LONG(rv_fake.calls, 1);
      CHECK_EQ_LONG(rv_fake.shell, 0);
      CHECK(strcmp(rv_fake.cmd, "id -u") == 0);
      CHECK(out != NULL && strstr(out, "rv-direct\n") != NULL);
      free(out);

      memset(&rv_fake, 0, sizeof(rv_fake));
      rv_fake.fail = 1;
      out = run_rv_entry(rv_loader, rv_loader_len, rv_exec, rv_exec_len,
                         rv_args, 1, &rv_fake);
      CHECK_EQ_LONG(rv_fake.calls, 1);
      CHECK(out != NULL && strstr(out, "exec: failed") != NULL);
      free(out);
    }
    free(rv_loader);
    free(rv_exec);
  }

  TEST_DONE();
  return 0;
}
