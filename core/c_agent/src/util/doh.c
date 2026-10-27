/*
 * doh.c — DNS-over-HTTPS resolver for the raw-socket transports.
 *
 * The DoH endpoint is queried with a minimal DNS wire message carried in an
 * HTTPS POST. libcurl is loaded at runtime through dynload, so a raw/libssl
 * build does not link curl. This file is only reached when the embedded agent
 * config contains a DoH URL; otherwise transports use libc getaddrinfo().
 */

#define _GNU_SOURCE

#include "util/doh.h"

#include "util/dynload.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* ---- minimal libcurl ABI (stable subset; no build-time curl headers) ---- */
typedef void CURL;
typedef long CURLcode;
typedef long CURLoption;
typedef struct curl_slist curl_slist;

struct curl_slist {
  char *data;
  struct curl_slist *next;
};

#define CURLOPTTYPE_LONG 0
#define CURLOPTTYPE_OBJECTPOINT 10000
#define CURLOPTTYPE_FUNCTIONPOINT 20000

#define CURLOPT_WRITEDATA (CURLOPTTYPE_OBJECTPOINT + 1)
#define CURLOPT_URL (CURLOPTTYPE_OBJECTPOINT + 2)
#define CURLOPT_WRITEFUNCTION (CURLOPTTYPE_FUNCTIONPOINT + 11)
#define CURLOPT_TIMEOUT (CURLOPTTYPE_LONG + 13)
#define CURLOPT_POSTFIELDS (CURLOPTTYPE_OBJECTPOINT + 15)
#define CURLOPT_HTTPHEADER (CURLOPTTYPE_OBJECTPOINT + 23)
#define CURLOPT_POST (CURLOPTTYPE_LONG + 47)
#define CURLOPT_POSTFIELDSIZE (CURLOPTTYPE_LONG + 60)
#define CURLOPT_SSL_VERIFYPEER (CURLOPTTYPE_LONG + 64)
#define CURLOPT_CONNECTTIMEOUT (CURLOPTTYPE_LONG + 78)
#define CURLOPT_SSL_VERIFYHOST (CURLOPTTYPE_LONG + 81)
#define CURLOPT_NOSIGNAL (CURLOPTTYPE_LONG + 99)
#define CURLOPT_FOLLOWLOCATION (CURLOPTTYPE_LONG + 52)

#define CURLE_OK 0

typedef size_t (*curl_write_cb)(char *, size_t, size_t, void *);
typedef CURL *(*curl_easy_init_fn)(void);
typedef CURLcode (*curl_easy_setopt_fn)(CURL *, CURLoption, ...);
typedef CURLcode (*curl_easy_perform_fn)(CURL *);
typedef void (*curl_easy_cleanup_fn)(CURL *);
typedef CURLcode (*curl_easy_getinfo_fn)(CURL *, long, ...);
typedef curl_slist *(*curl_slist_append_fn)(curl_slist *, const char *);
typedef void (*curl_slist_free_all_fn)(curl_slist *);

#define CURLINFO_RESPONSE_CODE 0x200002

static struct {
  void *lib;
  curl_easy_init_fn easy_init;
  curl_easy_setopt_fn easy_setopt;
  curl_easy_perform_fn easy_perform;
  curl_easy_cleanup_fn easy_cleanup;
  curl_easy_getinfo_fn easy_getinfo;
  curl_slist_append_fn slist_append;
  curl_slist_free_all_fn slist_free_all;
  int ready;
  int failed;
} g_curl;

static int curl_load(void) {
  if (g_curl.ready)
    return 0;
  if (g_curl.failed)
    return -1;

  static const char *sonames[] = {"libcurl.so.4", "libcurl.so.5", "libcurl.so",
                                  NULL};
  dynload dl;
  dynload_reset(&dl);
  for (size_t i = 0; sonames[i] != NULL; i++) {
    g_curl.lib = dynload_open(&dl, sonames[i], RTLD_LAZY | RTLD_LOCAL);
    if (g_curl.lib != NULL)
      break;
  }
  if (g_curl.lib == NULL)
    goto fail;

#define LOAD(field, name)                                                      \
  do {                                                                         \
    void *p_ = dynload_sym(&dl, g_curl.lib, name);                             \
    if (p_ == NULL)                                                            \
      goto fail;                                                               \
    memcpy(&g_curl.field, &p_, sizeof(p_));                                    \
  } while (0)
  LOAD(easy_init, "curl_easy_init");
  LOAD(easy_setopt, "curl_easy_setopt");
  LOAD(easy_perform, "curl_easy_perform");
  LOAD(easy_cleanup, "curl_easy_cleanup");
  LOAD(easy_getinfo, "curl_easy_getinfo");
  LOAD(slist_append, "curl_slist_append");
  LOAD(slist_free_all, "curl_slist_free_all");
#undef LOAD
  g_curl.ready = 1;
  return 0;

fail:
  if (g_curl.lib != NULL)
    dynload_close(&dl, g_curl.lib);
  g_curl.lib = NULL;
  g_curl.failed = 1;
  return -1;
}

typedef struct {
  uint8_t *buf;
  size_t len;
  size_t cap;
} doh_resp;

static size_t doh_write_cb(char *ptr, size_t size, size_t nmemb, void *ud) {
  size_t total = size * nmemb;
  doh_resp *r = (doh_resp *)ud;
  if (r->len + total > r->cap)
    return 0;
  memcpy(r->buf + r->len, ptr, total);
  r->len += total;
  return total;
}

static int doh_post(const char *url, const uint8_t *query, size_t query_len,
                    uint8_t *resp, size_t resp_cap, size_t *resp_len) {
  *resp_len = 0;
  if (curl_load() != 0)
    return -1;

  CURL *easy = g_curl.easy_init();
  if (easy == NULL)
    return -1;

  curl_slist *headers = NULL;
  headers =
      g_curl.slist_append(headers, "Content-Type: application/dns-message");
  headers = g_curl.slist_append(headers, "Accept: application/dns-message");

  doh_resp rb = {resp, 0, resp_cap};
  g_curl.easy_setopt(easy, CURLOPT_URL, url);
  g_curl.easy_setopt(easy, CURLOPT_POST, 1L);
  g_curl.easy_setopt(easy, CURLOPT_POSTFIELDS, (const char *)query);
  g_curl.easy_setopt(easy, CURLOPT_POSTFIELDSIZE, (long)query_len);
  g_curl.easy_setopt(easy, CURLOPT_HTTPHEADER, headers);
  g_curl.easy_setopt(easy, CURLOPT_WRITEFUNCTION, doh_write_cb);
  g_curl.easy_setopt(easy, CURLOPT_WRITEDATA, &rb);
  g_curl.easy_setopt(easy, CURLOPT_FOLLOWLOCATION, 0L);
  g_curl.easy_setopt(easy, CURLOPT_NOSIGNAL, 1L);
  g_curl.easy_setopt(easy, CURLOPT_CONNECTTIMEOUT, 10L);
  g_curl.easy_setopt(easy, CURLOPT_TIMEOUT, 15L);
  g_curl.easy_setopt(easy, CURLOPT_SSL_VERIFYPEER, 1L);
  g_curl.easy_setopt(easy, CURLOPT_SSL_VERIFYHOST, 2L);

  CURLcode rc = g_curl.easy_perform(easy);
  long status = 0;
  g_curl.easy_getinfo(easy, CURLINFO_RESPONSE_CODE, &status);
  g_curl.easy_cleanup(easy);
  g_curl.slist_free_all(headers);

  if (rc != CURLE_OK || status != 200)
    return -1;
  *resp_len = rb.len;
  return 0;
}

static uint16_t random_id(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (uint16_t)(ts.tv_nsec ^ (ts.tv_sec * 2654435761u));
}

/* Encode a DNS name into a query buffer. */
static int put_dns_name(uint8_t *out, size_t cap, size_t *pos,
                        const char *host) {
  size_t start = *pos;
  const char *p = host;
  while (*p) {
    const char *dot = strchr(p, '.');
    size_t len = dot != NULL ? (size_t)(dot - p) : strlen(p);
    if (len == 0 || len > 63 || *pos + 1 + len > cap)
      return -1;
    out[(*pos)++] = (uint8_t)len;
    memcpy(out + *pos, p, len);
    *pos += len;
    if (dot == NULL)
      break;
    p = dot + 1;
  }
  if (*pos + 1 > cap || *pos == start)
    return -1;
  out[(*pos)++] = 0;
  return 0;
}

static int build_query(const char *host, uint16_t qtype, uint16_t id,
                       uint8_t *out, size_t cap, size_t *out_len) {
  size_t p = 0;
  if (cap < 12)
    return -1;
  out[p++] = (uint8_t)(id >> 8);
  out[p++] = (uint8_t)id;
  out[p++] = 0x01; /* RD */
  out[p++] = 0x00;
  out[p++] = 0x00;
  out[p++] = 0x01; /* QDCOUNT */
  out[p++] = 0;
  out[p++] = 0;
  out[p++] = 0;
  out[p++] = 0;
  out[p++] = 0;
  out[p++] = 0;
  if (put_dns_name(out, cap, &p, host) != 0 || p + 4 > cap)
    return -1;
  out[p++] = (uint8_t)(qtype >> 8);
  out[p++] = (uint8_t)qtype;
  out[p++] = 0;
  out[p++] = 1; /* IN */
  *out_len = p;
  return 0;
}

static uint16_t rd16(const uint8_t *p) {
  return (uint16_t)(((uint16_t)p[0] << 8) | p[1]);
}

/* Skip a possibly compressed DNS name. */
static int skip_name(const uint8_t *p, size_t len, size_t *pos) {
  while (*pos < len) {
    uint8_t c = p[*pos];
    if ((c & 0xc0) == 0xc0) {
      if (*pos + 1 >= len)
        return -1;
      *pos += 2;
      return 0;
    }
    if (c == 0) {
      (*pos)++;
      return 0;
    }
    if (c > 63 || *pos + 1 + c > len)
      return -1;
    *pos += 1 + c;
  }
  return -1;
}

static int add_addr(c2_doh_addrs *out, const struct sockaddr *addr,
                    socklen_t addr_len, int family, int socktype) {
  if (out->count >= C2_DOH_MAX_ADDRS)
    return 0;
  for (size_t i = 0; i < out->count; i++) {
    if (out->addrs[i].addr_len == addr_len &&
        memcmp(&out->addrs[i].addr, addr, addr_len) == 0)
      return 0;
  }
  c2_doh_addr *dst = &out->addrs[out->count++];
  memcpy(&dst->addr, addr, addr_len);
  dst->addr_len = addr_len;
  dst->family = family;
  dst->socktype = socktype;
  dst->protocol = socktype == SOCK_STREAM ? IPPROTO_TCP : IPPROTO_UDP;
  return 0;
}

static int parse_response(const uint8_t *p, size_t len, uint16_t id,
                          uint16_t qtype, uint16_t port, int socktype,
                          c2_doh_addrs *out) {
  if (len < 12 || rd16(p) != id || (p[2] & 0x80) == 0 || (p[3] & 0x0f) != 0)
    return -1;
  uint16_t qd = rd16(p + 4);
  uint16_t an = rd16(p + 6);
  size_t pos = 12;
  for (uint16_t i = 0; i < qd; i++) {
    if (skip_name(p, len, &pos) != 0 || pos + 4 > len)
      return -1;
    pos += 4;
  }
  for (uint16_t i = 0; i < an; i++) {
    if (skip_name(p, len, &pos) != 0 || pos + 10 > len)
      return -1;
    uint16_t type = rd16(p + pos);
    uint16_t class_ = rd16(p + pos + 2);
    uint16_t rdlen = rd16(p + pos + 8);
    pos += 10;
    if (pos + rdlen > len)
      return -1;
    if (class_ != 1 || type != qtype) {
      pos += rdlen;
      continue;
    }
    if (type == 1 && rdlen == 4 && socktype == SOCK_STREAM) {
      struct sockaddr_in sin;
      memset(&sin, 0, sizeof(sin));
      sin.sin_family = AF_INET;
      sin.sin_port = htons(port);
      memcpy(&sin.sin_addr, p + pos, 4);
      add_addr(out, (const struct sockaddr *)&sin, sizeof(sin), AF_INET,
               socktype);
    } else if (type == 28 && rdlen == 16) {
      struct sockaddr_in6 sin6;
      memset(&sin6, 0, sizeof(sin6));
      sin6.sin6_family = AF_INET6;
      sin6.sin6_port = htons(port);
      memcpy(&sin6.sin6_addr, p + pos, 16);
      add_addr(out, (const struct sockaddr *)&sin6, sizeof(sin6), AF_INET6,
               socktype);
    }
    pos += rdlen;
  }
  return 0;
}

static int resolve_type(const char *url, const char *host, uint16_t qtype,
                        uint16_t port, int socktype, c2_doh_addrs *out) {
  uint8_t query[512];
  uint8_t response[65536];
  size_t qlen = 0, rlen = 0;
  uint16_t id = random_id();
  if (build_query(host, qtype, id, query, sizeof(query), &qlen) != 0)
    return -1;
  if (doh_post(url, query, qlen, response, sizeof(response), &rlen) != 0)
    return -1;
  return parse_response(response, rlen, id, qtype, port, socktype, out);
}

static int numeric_host(const char *host, const char *port, int socktype,
                        c2_doh_addrs *out) {
  unsigned long p = strtoul(port, NULL, 10);
  if (p == 0 || p > 65535)
    return -1;
  struct in_addr a4;
  if (inet_pton(AF_INET, host, &a4) == 1) {
    struct sockaddr_in sin;
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = htons((uint16_t)p);
    sin.sin_addr = a4;
    return add_addr(out, (const struct sockaddr *)&sin, sizeof(sin), AF_INET,
                    socktype) == 0
               ? 0
               : -1;
  }
  struct in6_addr a6;
  if (inet_pton(AF_INET6, host, &a6) == 1) {
    struct sockaddr_in6 sin6;
    memset(&sin6, 0, sizeof(sin6));
    sin6.sin6_family = AF_INET6;
    sin6.sin6_port = htons((uint16_t)p);
    sin6.sin6_addr = a6;
    return add_addr(out, (const struct sockaddr *)&sin6, sizeof(sin6), AF_INET6,
                    socktype) == 0
               ? 0
               : -1;
  }
  return -1;
}

int c2_doh_resolve(const c2_str *doh_url, const char *host, const char *port,
                   int socktype, c2_doh_addrs *out) {
  if (doh_url == NULL || host == NULL || port == NULL || out == NULL)
    return -1;
  memset(out, 0, sizeof(*out));
  if (doh_url->len == 0 || doh_url->ptr == NULL)
    return -1;

  if (numeric_host(host, port, socktype, out) == 0)
    return 0;

  char url[512];
  if (doh_url->len >= sizeof(url))
    return -1;
  memcpy(url, doh_url->ptr, doh_url->len);
  url[doh_url->len] = '\0';

  unsigned long p = strtoul(port, NULL, 10);
  if (p == 0 || p > 65535)
    return -1;
  uint16_t pnum = (uint16_t)p;

  /* A and AAAA; either family may be absent. */
  (void)resolve_type(url, host, 1, pnum, socktype, out);
  (void)resolve_type(url, host, 28, pnum, socktype, out);
  return out->count > 0 ? 0 : -1;
}

#ifdef DOH_FUZZ
int c2_doh_fuzz_parse(const uint8_t *data, size_t len) {
  if (data == NULL || len < 12)
    return 0;
  uint16_t id = rd16(data);
  uint16_t qtype = (len & 1) ? 28 : 1;
  c2_doh_addrs out;
  memset(&out, 0, sizeof(out));
  (void)parse_response(data, len, id, qtype, 443, SOCK_STREAM, &out);
  return 0;
}
#endif
