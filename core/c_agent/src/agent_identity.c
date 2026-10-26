/*
 * agent_identity.c — supervisor key hand-over for the hosted C agent.
 *
 * See include/agent_identity.h for the descriptor contract and why the key
 * must survive a recycled process.
 */

#include "agent_identity.h"

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

static int read_full(int fd, uint8_t *buf, size_t len, size_t *got) {
  size_t off = 0;
  while (off < len) {
    ssize_t n = read(fd, buf + off, len - off);
    if (n < 0) {
      if (errno == EINTR)
        continue;
      *got = off;
      return -1;
    }
    if (n == 0)
      break;
    off += (size_t)n;
  }
  *got = off;
  return 0;
}

static int write_full(int fd, const uint8_t *buf, size_t len) {
  size_t off = 0;
  while (off < len) {
    ssize_t n = write(fd, buf + off, len - off);
    if (n < 0) {
      if (errno == EINTR)
        continue;
      return -1;
    }
    if (n == 0)
      return -1;
    off += (size_t)n;
  }
  return 0;
}

int c2_agent_identity_supervisor_present(void) {
  return fcntl(C2_AGENT_KEY_FD_IN, F_GETFD) >= 0;
}

int c2_agent_identity_import(const c2_crypto_backend *be,
                             uint8_t priv[C2_AGENT_KEY_LEN],
                             uint8_t pub[C2_P256_PUB_BYTES]) {
  if (be == NULL || be->ec_p256_pub_from_priv == NULL || priv == NULL ||
      pub == NULL)
    return 0;

  uint8_t cached[C2_AGENT_KEY_LEN];
  size_t got = 0;
  int rc = read_full(C2_AGENT_KEY_FD_IN, cached, sizeof(cached), &got);
  if (rc != 0 || got != sizeof(cached)) {
    c2_secure_zero(cached, sizeof(cached));
    return 0;
  }

  if (be->ec_p256_pub_from_priv(be->ctx, cached, pub) != 0) {
    c2_secure_zero(cached, sizeof(cached));
    return -1;
  }
  memcpy(priv, cached, sizeof(cached));
  c2_secure_zero(cached, sizeof(cached));
  return 1;
}

void c2_agent_identity_export(const uint8_t priv[C2_AGENT_KEY_LEN]) {
  if (priv == NULL)
    return;
  (void)write_full(C2_AGENT_KEY_FD_OUT, priv, C2_AGENT_KEY_LEN);
}
