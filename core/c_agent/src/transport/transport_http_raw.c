/*
 * transport_http_raw.c — self-contained HTTP-poll transport over TCP.
 *
 * This transport implements the HTTP/1.1 request/response exchange itself on
 * top of libc TCP sockets: no libcurl, no OpenSSL, no external process. It is
 * selected with TRANSPORT=http_raw and supplies hp_http_perform() to the shared
 * http_poll state machine. HTTPS is intentionally unsupported; use the libcurl
 * transport (or a CDN that terminates TLS in front of a plain HTTP listener).
 */

#define _GNU_SOURCE

#include "http_wire.h"

#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#define RAW_HEADER_CAP (64u * 1024u)

typedef struct {
  uint8_t *p;
  size_t len;
  size_t cap;
} bytebuf;

static int bb_reserve(bytebuf *b, size_t extra) {
  if (extra > b->cap - b->len)
    return -1;
  return 0;
}

static int bb_put(bytebuf *b, const void *data, size_t len) {
  if (bb_reserve(b, len) != 0)
    return -1;
  memcpy(b->p + b->len, data, len);
  b->len += len;
  return 0;
}

static int bb_puts(bytebuf *b, const char *s) { return bb_put(b, s, strlen(s)); }

static int ci_eq_n(const char *a, size_t alen, const char *b) {
  size_t blen = strlen(b);
  if (alen != blen)
    return 0;
  for (size_t i = 0; i < alen; i++) {
    char x = a[i], y = b[i];
    if (x >= 'A' && x <= 'Z')
      x = (char)(x + 32);
    if (y >= 'A' && y <= 'Z')
      y = (char)(y + 32);
    if (x != y)
      return 0;
  }
  return 1;
}

static int is_reserved_header(const char *line) {
  const char *colon = strchr(line, ':');
  if (colon == NULL)
    return 0;
  size_t n = (size_t)(colon - line);
  return ci_eq_n(line, n, "host") || ci_eq_n(line, n, "connection") ||
         ci_eq_n(line, n, "content-length");
}

/* Parse http://host[:port][/path]. Returns 0 on success. */
int hp_http_parse_url(const char *url, char *host, size_t host_cap,
                      char *port, size_t port_cap, char *path, size_t path_cap,
                      char *authority, size_t auth_cap, int *tls) {
  if (url == NULL)
    return -1;
  int is_tls = 0;
  const char *a = NULL;
  if (strncmp(url, "http://", 7) == 0) {
    a = url + 7;
  } else if (strncmp(url, "https://", 8) == 0) {
    a = url + 8;
    is_tls = 1;
  } else {
    return -1;
  }
  if (tls != NULL)
    *tls = is_tls;
  const char *slash = strchr(a, '/');
  size_t alen = slash != NULL ? (size_t)(slash - a) : strlen(a);
  if (alen == 0 || alen >= auth_cap || alen >= host_cap + port_cap)
    return -1;
  memcpy(authority, a, alen);
  authority[alen] = '\0';

  const char *path_src = slash != NULL ? slash : "/";
  size_t plen = strlen(path_src);
  if (plen >= path_cap)
    return -1;
  memcpy(path, path_src, plen + 1);

  const char *h = a;
  size_t hlen = alen;
  const char *p = NULL;
  if (alen > 2 && a[0] == '[') {
    const char *close = memchr(a, ']', alen);
    if (close == NULL || close == a + 1)
      return -1;
    h = a + 1;
    hlen = (size_t)(close - h);
    if ((size_t)(close - a) + 1 < alen && close[1] == ':') {
      p = close + 2;
    }
  } else {
    const char *colon = memchr(a, ':', alen);
    if (colon != NULL) {
      h = a;
      hlen = (size_t)(colon - a);
      p = colon + 1;
    }
  }
  if (hlen == 0 || hlen >= host_cap)
    return -1;
  memcpy(host, h, hlen);
  host[hlen] = '\0';

  if (p != NULL) {
    size_t pl = (size_t)(a + alen - p);
    if (pl == 0 || pl >= port_cap)
      return -1;
    memcpy(port, p, pl);
    port[pl] = '\0';
  } else {
    if (port_cap < 3)
      return -1;
    memcpy(port, "80", 3);
  }
  return 0;
}

static int connect_with_timeout(int fd, const struct sockaddr *addr,
                                socklen_t addrlen, int timeout_s) {
  int flags = fcntl(fd, F_GETFL, 0);
  if (flags < 0)
    return -1;
  if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0)
    return -1;

  int rc = connect(fd, addr, addrlen);
  if (rc < 0 && errno != EINPROGRESS)
    return -1;
  if (rc < 0) {
    struct pollfd pfd = {.fd = fd, .events = POLLOUT};
    int wait_ms = timeout_s > 0 ? timeout_s * 1000 : 30000;
    do {
      rc = poll(&pfd, 1, wait_ms);
    } while (rc < 0 && errno == EINTR);
    if (rc <= 0)
      return -1;
    int err = 0;
    socklen_t elen = sizeof(err);
    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &elen) != 0 || err != 0)
      return -1;
  }
  if (fcntl(fd, F_SETFL, flags) < 0)
    return -1;
  return 0;
}

static void set_io_timeout(int fd, int timeout_s) {
  if (timeout_s <= 0)
    timeout_s = 30;
  struct timeval tv;
  tv.tv_sec = timeout_s;
  tv.tv_usec = 0;
  setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
  setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
}

static int raw_send_all(void *ctx, const uint8_t *buf, size_t len) {
  int fd = *(int *)ctx;
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

static int raw_recv_some(void *ctx, uint8_t *buf, size_t cap) {
  int fd = *(int *)ctx;
  for (;;) {
    ssize_t n = recv(fd, buf, cap, 0);
    if (n < 0 && errno == EINTR)
      continue;
    return n < 0 ? -1 : (int)n;
  }
}

/* Read the complete HTTP response until the peer closes the connection. */
static int read_all(const hp_http_io *io, bytebuf *out, size_t cap) {
  uint8_t tmp[8192];
  for (;;) {
    int n = io->recv_some(io->ctx, tmp, sizeof(tmp));
    if (n < 0)
      return -1;
    if (n == 0)
      return 0;
    if (out->len + (size_t)n > cap)
      return -1;
    if (bb_put(out, tmp, (size_t)n) != 0)
      return -1;
  }
}

static int header_value(const char *headers, size_t headers_len,
                        const char *name, char *out, size_t out_cap) {
  size_t nlen = strlen(name);
  size_t pos = 0;
  while (pos < headers_len) {
    size_t end = pos;
    while (end + 1 <= headers_len &&
           !(headers[end] == '\r' && headers[end + 1] == '\n'))
      end++;
    const char *line = headers + pos;
    size_t line_len = end - pos;
    if (line_len > nlen && line[nlen] == ':' &&
        ci_eq_n(line, nlen, name)) {
      const char *v = line + nlen + 1;
      size_t vlen = line_len - nlen - 1;
      while (vlen > 0 && (*v == ' ' || *v == '\t')) {
        v++;
        vlen--;
      }
      while (vlen > 0 && (v[vlen - 1] == ' ' || v[vlen - 1] == '\t'))
        vlen--;
      if (vlen >= out_cap)
        return -1;
      memcpy(out, v, vlen);
      out[vlen] = '\0';
      return 1;
    }
    pos = end + 2;
  }
  return 0;
}

/* Decode a chunked response body into req->resp. */
static int decode_chunked(const uint8_t *body, size_t body_len,
                          hp_http_request *req, size_t *out_len) {
  size_t pos = 0;
  size_t out = 0;
  while (pos < body_len) {
    size_t line_end = pos;
    while (line_end + 1 < body_len &&
           !(body[line_end] == '\r' && body[line_end + 1] == '\n'))
      line_end++;
    if (line_end + 1 >= body_len)
      return -1;
    char sizebuf[32];
    size_t n = 0;
    while (pos < line_end && n + 1 < sizeof(sizebuf)) {
      char c = (char)body[pos++];
      if (c == ';')
        break;
      sizebuf[n++] = c;
    }
    /* Skip any chunk extension to the end of the line. */
    pos = line_end + 2;
    sizebuf[n] = '\0';
    char *endp = NULL;
    unsigned long chunk = strtoul(sizebuf, &endp, 16);
    if (endp == sizebuf)
      return -1;
    if (chunk == 0) {
      *out_len = out;
      return 0;
    }
    if (chunk > body_len - pos)
      return -1;
    if (chunk > req->resp_cap - out)
      return -1;
    memcpy(req->resp + out, body + pos, (size_t)chunk);
    out += (size_t)chunk;
    pos += (size_t)chunk;
    if (pos + 1 >= body_len || body[pos] != '\r' || body[pos + 1] != '\n')
      return -1;
    pos += 2;
  }
  return -1;
}

static c2_status parse_response(hp_http_request *req, const uint8_t *raw,
                                size_t raw_len) {
  const char *text = (const char *)raw;
  const char *hdr_end = strstr(text, "\r\n\r\n");
  if (hdr_end == NULL)
    return C2_ERR_IO;
  size_t headers_len = (size_t)(hdr_end - text);
  const char *status_line = text;
  if (headers_len < 12 || strncmp(status_line, "HTTP/", 5) != 0)
    return C2_ERR_IO;
  char *endp = NULL;
  long status = strtol(status_line + 8, &endp, 10);
  if (endp == status_line + 8 || status < 100 || status > 999)
    return C2_ERR_IO;
  *req->status = status;

  const uint8_t *body = (const uint8_t *)(hdr_end + 4);
  size_t body_len = raw_len - (size_t)(body - raw);
  char hval[128];
  int has_len = header_value(text, headers_len, "Content-Length", hval,
                             sizeof(hval));
  if (has_len < 0)
    return C2_ERR_IO;
  if (has_len > 0) {
    char *e = NULL;
    unsigned long long want = strtoull(hval, &e, 10);
    if (e == hval)
      return C2_ERR_IO;
    if (want > req->resp_cap)
      return C2_ERR_NOMEM;
    if ((unsigned long long)body_len < want)
      return C2_ERR_IO;
    memcpy(req->resp, body, (size_t)want);
    *req->resp_len = (size_t)want;
    return C2_OK;
  }

  int chunked = header_value(text, headers_len, "Transfer-Encoding", hval,
                             sizeof(hval));
  if (chunked < 0)
    return C2_ERR_IO;
  if (chunked > 0 && ci_eq_n(hval, strlen(hval), "chunked")) {
    size_t out = 0;
    if (decode_chunked(body, body_len, req, &out) != 0)
      return C2_ERR_NOMEM;
    *req->resp_len = out;
    return C2_OK;
  }

  if (body_len > req->resp_cap)
    return C2_ERR_NOMEM;
  memcpy(req->resp, body, body_len);
  *req->resp_len = body_len;
  return C2_OK;
}

c2_status hp_http_exchange(const hp_http_request *req, const char *path,
                           const char *authority, const hp_http_io *io) {
  if (req == NULL || path == NULL || authority == NULL || io == NULL ||
      io->send_all == NULL || io->recv_some == NULL)
    return C2_ERR_ARG;

  size_t hdr_bytes = 0;
  for (size_t i = 0; i < req->header_count; i++)
    hdr_bytes += strlen(req->headers[i]) + 2;
  size_t cap = 512 + strlen(path) + strlen(authority) + hdr_bytes +
               (req->body ? req->body_len : 0);
  bytebuf out = {malloc(cap), 0, cap};
  if (out.p == NULL)
    return C2_ERR_NOMEM;

  int rc = bb_puts(&out, req->method);
  rc |= bb_put(&out, " ", 1);
  rc |= bb_puts(&out, path);
  rc |= bb_puts(&out, " HTTP/1.1\r\nHost: ");
  rc |= bb_puts(&out, authority);
  rc |= bb_puts(&out, "\r\nConnection: close\r\n");
  for (size_t i = 0; i < req->header_count && rc == 0; i++) {
    if (is_reserved_header(req->headers[i]))
      continue;
    rc |= bb_puts(&out, req->headers[i]);
    rc |= bb_puts(&out, "\r\n");
  }
  if (req->method[0] != 'G') {
    char lenbuf[32];
    int n = snprintf(lenbuf, sizeof(lenbuf), "Content-Length: %zu\r\n",
                     req->body_len);
    if (n < 0 || (size_t)n >= sizeof(lenbuf))
      rc = -1;
    else
      rc |= bb_put(&out, lenbuf, (size_t)n);
  }
  rc |= bb_puts(&out, "\r\n");
  if (rc == 0 && req->body_len > 0)
    rc = bb_put(&out, req->body, req->body_len);
  if (rc == 0)
    rc = io->send_all(io->ctx, out.p, out.len);
  free(out.p);
  if (rc != 0)
    return C2_ERR_IO;

  size_t raw_cap = req->resp_cap + RAW_HEADER_CAP;
  bytebuf raw = {malloc(raw_cap + 1), 0, raw_cap};
  if (raw.p == NULL)
    return C2_ERR_NOMEM;
  int read_rc = read_all(io, &raw, raw_cap);
  if (read_rc != 0) {
    free(raw.p);
    return C2_ERR_IO;
  }
  raw.p[raw.len] = '\0';

  hp_http_request local = *req;
  c2_status st = parse_response(&local, raw.p, raw.len);
  free(raw.p);
  return st;
}

int hp_http_tcp_connect(const char *host, const char *port, int timeout_s) {
  struct addrinfo hints;
  memset(&hints, 0, sizeof(hints));
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_family = AF_UNSPEC;
  struct addrinfo *res = NULL;
  if (getaddrinfo(host, port, &hints, &res) != 0 || res == NULL)
    return -1;

  int fd = -1;
  for (struct addrinfo *ai = res; ai != NULL; ai = ai->ai_next) {
    fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
    if (fd < 0)
      continue;
    set_io_timeout(fd, timeout_s);
    if (connect_with_timeout(fd, ai->ai_addr, ai->ai_addrlen, timeout_s) == 0)
      break;
    close(fd);
    fd = -1;
  }
  freeaddrinfo(res);
  return fd;
}

c2_status hp_http_raw_perform(const hp_http_request *req) {
  if (req == NULL || req->url == NULL || req->method == NULL ||
      req->resp == NULL || req->resp_len == NULL || req->status == NULL)
    return C2_ERR_ARG;
  *req->resp_len = 0;
  *req->status = 0;

  char host[256], port[16], path[2048], authority[300];
  int tls = 0;
  if (hp_http_parse_url(req->url, host, sizeof(host), port, sizeof(port), path,
                        sizeof(path), authority, sizeof(authority), &tls) != 0)
    return C2_ERR_UNSUPPORTED;
  if (tls)
    return C2_ERR_UNSUPPORTED; /* the libssl transport handles https */

  int fd = hp_http_tcp_connect(host, port, (int)req->timeout_s);
  if (fd < 0)
    return C2_ERR_IO;

  hp_http_io io = {&fd, raw_send_all, raw_recv_some};
  c2_status st = hp_http_exchange(req, path, authority, &io);
  close(fd);
  return st;
}

#ifndef HP_HTTP_RAW_AS_HELPER
c2_status hp_http_perform(const hp_http_request *req) {
  return hp_http_raw_perform(req);
}

const char *c2_transport_name(void) { return "http_raw"; }
#endif
