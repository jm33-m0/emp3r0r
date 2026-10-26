#define _GNU_SOURCE

/*
 * test_identity.c — the supervisor key hand-over used by recycled children.
 *
 * FDs 100/101 are redirected to pipes for the duration of each case, with any
 * previously open descriptor saved and restored afterwards. The crypto backend
 * is the deterministic stub: the point is the descriptor protocol, not P-256
 * (which test_crypto covers against the real backend).
 */

#include "agent_identity.h"

#include "stub_crypto.h"

#include "test.h"

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

static int save_fd(int fd) {
  int n = fcntl(fd, F_DUPFD_CLOEXEC, 200);
  return n < 0 ? -1 : n;
}

static void restore_fd(int fd, int saved) {
  if (saved >= 0) {
    (void)dup2(saved, fd);
    close(saved);
  } else {
    close(fd);
  }
}

static int write_all(int fd, const uint8_t *b, size_t n) {
  size_t off = 0;
  while (off < n) {
    ssize_t w = write(fd, b + off, n - off);
    if (w <= 0)
      return -1;
    off += (size_t)w;
  }
  return 0;
}

static int read_all(int fd, uint8_t *b, size_t n) {
  size_t off = 0;
  while (off < n) {
    ssize_t r = read(fd, b + off, n - off);
    if (r <= 0)
      return -1;
    off += (size_t)r;
  }
  return 0;
}

int main(void) {
  c2_crypto_backend be;
  uint32_t rng = 1;
  stub_crypto_init(&be, &rng);

  int saved_in = save_fd(C2_AGENT_KEY_FD_IN);
  int saved_out = save_fd(C2_AGENT_KEY_FD_OUT);

  /* A cached key is restored byte-for-byte and handed back to the parent. */
  {
    int kin[2], kout[2];
    CHECK_EQ_LONG(pipe(kin), 0);
    CHECK_EQ_LONG(pipe(kout), 0);
    CHECK_EQ_LONG(dup2(kin[0], C2_AGENT_KEY_FD_IN), C2_AGENT_KEY_FD_IN);
    CHECK_EQ_LONG(dup2(kout[1], C2_AGENT_KEY_FD_OUT), C2_AGENT_KEY_FD_OUT);
    close(kin[0]);
    close(kout[1]);

    uint8_t key[C2_AGENT_KEY_LEN];
    for (size_t i = 0; i < sizeof(key); i++)
      key[i] = (uint8_t)(i * 3u + 7u);
    CHECK_EQ_LONG(write_all(kin[1], key, sizeof(key)), 0);
    close(kin[1]);

    uint8_t priv[C2_AGENT_KEY_LEN], pub[C2_P256_PUB_BYTES];
    memset(priv, 0, sizeof(priv));
    memset(pub, 0, sizeof(pub));
    CHECK_EQ_LONG(c2_agent_identity_import(&be, priv, pub), 1);
    CHECK_BYTES(priv, key, sizeof(key));
    uint8_t want_pub[C2_P256_PUB_BYTES];
    CHECK_EQ_LONG(be.ec_p256_pub_from_priv(be.ctx, key, want_pub), 0);
    CHECK_BYTES(pub, want_pub, sizeof(pub));

    c2_agent_identity_export(priv);
    uint8_t exported[C2_AGENT_KEY_LEN];
    CHECK_EQ_LONG(read_all(kout[0], exported, sizeof(exported)), 0);
    CHECK_BYTES(exported, key, sizeof(key));
    close(kout[0]);
  }

  /* EOF (first lifecycle) means "generate", not an error. */
  {
    int kin[2];
    CHECK_EQ_LONG(pipe(kin), 0);
    CHECK_EQ_LONG(dup2(kin[0], C2_AGENT_KEY_FD_IN), C2_AGENT_KEY_FD_IN);
    close(kin[0]);
    close(kin[1]);

    uint8_t priv[C2_AGENT_KEY_LEN], pub[C2_P256_PUB_BYTES];
    CHECK_EQ_LONG(c2_agent_identity_import(&be, priv, pub), 0);
  }

  restore_fd(C2_AGENT_KEY_FD_IN, saved_in);
  restore_fd(C2_AGENT_KEY_FD_OUT, saved_out);
  TEST_DONE();
}
