/*
 * test_socks5_bof.c — the socks5 BOF through the real loaders.
 *
 * The BOF owns its whole side: it parses the target, resolves it, dials it and
 * only then hands the socket to RelaySocket. This checks each of those steps
 * against a real loopback listener, with the agent's relay replaced by a
 * recording callback, and repeats it as an RV32 guest through the syscall gate.
 */

#define _POSIX_C_SOURCE 200809L

#include "bof.h"
#include "rvvm.h"

#include "test.h"

#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#ifndef BOF_LOADER_PATH
#define BOF_LOADER_PATH ""
#endif
#ifndef BOF_SOCKS5_PATH
#define BOF_SOCKS5_PATH ""
#endif
#ifndef RVVM_LOADER_PATH
#define RVVM_LOADER_PATH ""
#endif
#ifndef RV_SOCKS5_PATH
#define RV_SOCKS5_PATH ""
#endif

typedef struct {
  char token[128];
  int calls;
  int fd;
  int idle_seconds;
  unsigned short peer_port;
  /* Non-zero makes the callback refuse, like a host that cannot relay. */
  int fail;
} fake_host;

/* Takes ownership of `fd`, like the real relay does. `peer_port` records where
 * the BOF's dial actually landed. */
static int fake_relay(void *vctx, const char *token, int fd, int idle_seconds,
                      char *err, int err_cap) {
  fake_host *h = (fake_host *)vctx;
  h->calls++;
  h->fd = fd;
  h->idle_seconds = idle_seconds;
  snprintf(h->token, sizeof(h->token), "%s", token != NULL ? token : "");
  h->peer_port = 0;
  struct sockaddr_in peer;
  socklen_t peer_len = sizeof(peer);
  if (fd < 0 || getpeername(fd, (struct sockaddr *)&peer, &peer_len) != 0) {
    if (err != NULL && err_cap > 0)
      snprintf(err, (size_t)err_cap, "socket is not connected");
    if (fd >= 0)
      close(fd);
    return -1;
  }
  h->peer_port = ntohs(peer.sin_port);
  if (h->fail) {
    if (err != NULL && err_cap > 0)
      snprintf(err, (size_t)err_cap, "relay refused");
    close(fd);
    return -1;
  }
  /* The real relay closes the socket when the connection ends. */
  close(fd);
  return 0;
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
  c2_bof_host host = {fake, NULL, NULL, NULL, NULL, fake_relay, NULL};
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
  c2_bof_host host = {fake, NULL, NULL, NULL, NULL, fake_relay, NULL};
  char *out = NULL;
  c2_status st = c2_rv_run(loader, loader_len, image, image_len, packed,
                           packed_len, &host, &out);
  if (st != C2_OK && out != NULL)
    fprintf(stderr, "  rv failed: %s\n", out);
  CHECK_EQ_LONG(st, C2_OK);
  return out;
}

/* A loopback listener the BOF can dial; returns its port or 0. */
static unsigned short listen_loopback(int *fd_out) {
  int fd = socket(AF_INET, SOCK_STREAM, 0);
  if (fd < 0)
    return 0;
  struct sockaddr_in addr;
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  addr.sin_port = 0;
  if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0 ||
      listen(fd, 4) != 0) {
    close(fd);
    return 0;
  }
  socklen_t len = sizeof(addr);
  if (getsockname(fd, (struct sockaddr *)&addr, &len) != 0) {
    close(fd);
    return 0;
  }
  *fd_out = fd;
  return ntohs(addr.sin_port);
}

int main(void) {
  if (BOF_LOADER_PATH[0] == '\0' || BOF_SOCKS5_PATH[0] == '\0') {
    printf("%s: loader/object not provided, skipped\n", __FILE__);
    TEST_DONE();
    return 0;
  }

  size_t loader_len = 0, socks5_len = 0;
  unsigned char *loader = slurp(BOF_LOADER_PATH, &loader_len);
  unsigned char *socks5 = slurp(BOF_SOCKS5_PATH, &socks5_len);
  CHECK(loader != NULL && loader_len > 0);
  CHECK(socks5 != NULL && socks5_len > 0);
  if (loader == NULL || socks5 == NULL) {
    free(loader);
    free(socks5);
    TEST_DONE();
    return 0;
  }

  int listener = -1;
  unsigned short port = listen_loopback(&listener);
  CHECK(port != 0);
  char target[64];
  snprintf(target, sizeof(target), "127.0.0.1:%u", (unsigned)port);
  char target_arg[80];
  snprintf(target_arg, sizeof(target_arg), "z%s", target);

  fake_host fake;
  memset(&fake, 0, sizeof(fake));
  char *out = NULL;

  /* The BOF parses, resolves and dials, then hands the connected socket over
   * with the module's own idle deadline. */
  c2_str ok_args[2] = {c2_str_lit("zproxy-token-1"),
                       c2_str_of(target_arg, strlen(target_arg))};
  out = run_entry(loader, loader_len, socks5, socks5_len, ok_args, 2, &fake);
  CHECK_EQ_LONG(fake.calls, 1);
  CHECK(strcmp(fake.token, "proxy-token-1") == 0);
  CHECK_EQ_LONG(fake.peer_port, (long)port);
  CHECK_EQ_LONG(fake.idle_seconds, 15 * 60);
  CHECK(out != NULL && strstr(out, "socks5: relay started") != NULL);
  free(out);

  /* A refused relay reports the host's reason, not a success line. */
  memset(&fake, 0, sizeof(fake));
  fake.fail = 1;
  out = run_entry(loader, loader_len, socks5, socks5_len, ok_args, 2, &fake);
  CHECK_EQ_LONG(fake.calls, 1);
  CHECK(out != NULL && strstr(out, "socks5: relay refused") != NULL);
  CHECK(out == NULL || strstr(out, "relay started") == NULL);
  free(out);

  /* An unreachable port fails in the dial, before any relay is asked for. */
  memset(&fake, 0, sizeof(fake));
  c2_str closed_args[2] = {c2_str_lit("ztok"), c2_str_lit("z127.0.0.1:1")};
  out =
      run_entry(loader, loader_len, socks5, socks5_len, closed_args, 2, &fake);
  CHECK_EQ_LONG(fake.calls, 0);
  CHECK(out != NULL && strstr(out, "cannot connect to") != NULL);
  free(out);

  /* An IPv6 literal is split, not rejected: the dial is what fails here. */
  memset(&fake, 0, sizeof(fake));
  c2_str v6_args[2] = {c2_str_lit("ztok"), c2_str_lit("z[::1]:1")};
  out = run_entry(loader, loader_len, socks5, socks5_len, v6_args, 2, &fake);
  CHECK_EQ_LONG(fake.calls, 0);
  CHECK(out != NULL && strstr(out, "cannot connect to") != NULL);
  CHECK(out == NULL || strstr(out, "invalid target") == NULL);
  free(out);

  /* Malformed targets never reach the resolver. */
  const char *bad_targets[] = {
      "zno-port",         "z127.0.0.1:", "z127.0.0.1:0",
      "z127.0.0.1:70000", "z:80",        "z[::1:80"};
  for (size_t i = 0; i < sizeof(bad_targets) / sizeof(bad_targets[0]); i++) {
    memset(&fake, 0, sizeof(fake));
    c2_str bad[2] = {c2_str_lit("ztok"),
                     c2_str_of(bad_targets[i], strlen(bad_targets[i]))};
    out = run_entry(loader, loader_len, socks5, socks5_len, bad, 2, &fake);
    CHECK(out != NULL && strstr(out, "invalid target") != NULL);
    CHECK_EQ_LONG(fake.calls, 0);
    free(out);
  }

  /* Missing arguments are refused before the host is asked to relay. */
  memset(&fake, 0, sizeof(fake));
  c2_str no_token[2] = {c2_str_lit("z"),
                        c2_str_of(target_arg, strlen(target_arg))};
  out = run_entry(loader, loader_len, socks5, socks5_len, no_token, 2, &fake);
  CHECK(out != NULL && strstr(out, "missing proxy stream token") != NULL);
  CHECK_EQ_LONG(fake.calls, 0);
  free(out);

  c2_str no_target[2] = {c2_str_lit("ztok"), c2_str_lit("z")};
  out = run_entry(loader, loader_len, socks5, socks5_len, no_target, 2, &fake);
  CHECK(out != NULL && strstr(out, "missing target") != NULL);
  CHECK_EQ_LONG(fake.calls, 0);
  free(out);

  free(loader);
  free(socks5);
  close(listener);

  /* The same object dials and relays as an RV32 guest: resolution, connect,
   * poll and getsockopt all cross the syscall gate. */
  if (RVVM_LOADER_PATH[0] != '\0' && RV_SOCKS5_PATH[0] != '\0') {
    size_t rv_loader_len = 0, rv_socks5_len = 0;
    unsigned char *rv_loader = slurp(RVVM_LOADER_PATH, &rv_loader_len);
    unsigned char *rv_socks5 = slurp(RV_SOCKS5_PATH, &rv_socks5_len);
    CHECK(rv_loader != NULL && rv_loader_len > 0);
    CHECK(rv_socks5 != NULL && rv_socks5_len > 0);
    if (rv_loader != NULL && rv_socks5 != NULL) {
      int rv_listener = -1;
      unsigned short rv_port = listen_loopback(&rv_listener);
      CHECK(rv_port != 0);
      char rv_target[80];
      snprintf(rv_target, sizeof(rv_target), "z127.0.0.1:%u",
               (unsigned)rv_port);

      fake_host rv_fake;
      memset(&rv_fake, 0, sizeof(rv_fake));
      c2_str rv_args[2] = {c2_str_lit("zproxy-token-rv"),
                           c2_str_of(rv_target, strlen(rv_target))};
      out = run_rv_entry(rv_loader, rv_loader_len, rv_socks5, rv_socks5_len,
                         rv_args, 2, &rv_fake);
      CHECK_EQ_LONG(rv_fake.calls, 1);
      CHECK(strcmp(rv_fake.token, "proxy-token-rv") == 0);
      CHECK_EQ_LONG(rv_fake.peer_port, (long)rv_port);
      CHECK_EQ_LONG(rv_fake.idle_seconds, 15 * 60);
      CHECK(out != NULL && strstr(out, "socks5: relay started") != NULL);
      free(out);

      /* The guest has no error channel, so a refused dial is a bare failure. */
      rv_fake.fail = 0;
      memset(&rv_fake, 0, sizeof(rv_fake));
      c2_str rv_closed[2] = {c2_str_lit("ztok"), c2_str_lit("z127.0.0.1:1")};
      out = run_rv_entry(rv_loader, rv_loader_len, rv_socks5, rv_socks5_len,
                         rv_closed, 2, &rv_fake);
      CHECK_EQ_LONG(rv_fake.calls, 0);
      CHECK(out != NULL && strstr(out, "cannot connect to") != NULL);
      free(out);

      close(rv_listener);
    }
    free(rv_loader);
    free(rv_socks5);
  }

  TEST_DONE();
  return 0;
}
