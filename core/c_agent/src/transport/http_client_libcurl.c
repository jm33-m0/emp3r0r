/*
 * http_client_libcurl.c — c2_http_client provider over the system libcurl.
 *
 * libcurl is resolved at runtime with dynload.h (the same mechanism the stager
 * uses), so there is no build-time dependency on curl and the small stable ABI
 * subset is declared inline. libcurl also provides the TLS stack for an https
 * URL. This is the default `HTTP=libcurl` provider.
 */

#define _POSIX_C_SOURCE 200809L

#include "http_client.h"

#include "util/dynload.h"

#include <stdlib.h>
#include <string.h>

/* ---- minimal libcurl ABI (values from <curl/curl.h>, stable) ---- */
typedef void CURL;
typedef long CURLcode;
typedef long CURLoption;
typedef long CURLINFO;
typedef struct curl_slist curl_slist;

struct curl_slist {
  char *data;
  struct curl_slist *next;
};

struct curl_blob {
  void *data;
  size_t len;
  unsigned int flags;
};

#define CURLOPTTYPE_LONG 0
#define CURLOPTTYPE_OBJECTPOINT 10000
#define CURLOPTTYPE_FUNCTIONPOINT 20000
#define CURLOPTTYPE_BLOB 40000

#define CURLOPT_WRITEDATA (CURLOPTTYPE_OBJECTPOINT + 1)
#define CURLOPT_URL (CURLOPTTYPE_OBJECTPOINT + 2)
#define CURLOPT_WRITEFUNCTION (CURLOPTTYPE_FUNCTIONPOINT + 11)
#define CURLOPT_TIMEOUT (CURLOPTTYPE_LONG + 13)
#define CURLOPT_POSTFIELDS (CURLOPTTYPE_OBJECTPOINT + 15)
#define CURLOPT_HTTPHEADER (CURLOPTTYPE_OBJECTPOINT + 23)
#define CURLOPT_POST (CURLOPTTYPE_LONG + 47)
#define CURLOPT_FOLLOWLOCATION (CURLOPTTYPE_LONG + 52)
#define CURLOPT_POSTFIELDSIZE (CURLOPTTYPE_LONG + 60)
#define CURLOPT_SSL_VERIFYPEER (CURLOPTTYPE_LONG + 64)
#define CURLOPT_CAINFO (CURLOPTTYPE_OBJECTPOINT + 65)
#define CURLOPT_CONNECTTIMEOUT (CURLOPTTYPE_LONG + 78)
#define CURLOPT_HTTPGET (CURLOPTTYPE_LONG + 80)
#define CURLOPT_SSL_VERIFYHOST (CURLOPTTYPE_LONG + 81)
#define CURLOPT_NOSIGNAL (CURLOPTTYPE_LONG + 99)
#define CURLOPT_CAINFO_BLOB (CURLOPTTYPE_BLOB + 309)
#define CURL_BLOB_COPY 1
#define CURLINFO_RESPONSE_CODE 0x200002

#define CURLE_OK 0
#define CURL_GLOBAL_ALL 3

typedef size_t (*curl_write_cb)(char *, size_t, size_t, void *);
typedef CURL *(*curl_easy_init_fn)(void);
typedef CURLcode (*curl_easy_setopt_fn)(CURL *, CURLoption, ...);
typedef CURLcode (*curl_easy_perform_fn)(CURL *);
typedef void (*curl_easy_cleanup_fn)(CURL *);
typedef CURLcode (*curl_easy_getinfo_fn)(CURL *, CURLINFO, ...);
typedef curl_slist *(*curl_slist_append_fn)(curl_slist *, const char *);
typedef void (*curl_slist_free_all_fn)(curl_slist *);
typedef CURLcode (*curl_global_init_fn)(long);

/* libcurl is resolved once and kept for the process lifetime; the agent is
 * single-threaded, so no lock is needed. */
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

  curl_global_init_fn global_init =
      (curl_global_init_fn)(uintptr_t)dynload_sym(&dl, g_curl.lib,
                                                  "curl_global_init");
  if (global_init != NULL)
    global_init(CURL_GLOBAL_ALL);

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
} resp_buf;

static size_t write_cb(char *ptr, size_t size, size_t nmemb, void *ud) {
  size_t total = size * nmemb;
  resp_buf *r = (resp_buf *)ud;
  if (r->len + total > r->cap)
    return 0; /* abort: over the cap */
  memcpy(r->buf + r->len, ptr, total);
  r->len += total;
  return total;
}

c2_status c2_http_client_perform(const c2_http_request *req) {
  if (req == NULL || req->url == NULL || req->method == NULL ||
      req->resp == NULL || req->resp_len == NULL || req->status == NULL)
    return C2_ERR_ARG;
  if (curl_load() != 0)
    return C2_ERR_UNSUPPORTED;

  CURL *easy = g_curl.easy_init();
  if (easy == NULL)
    return C2_ERR_IO;

  curl_slist *headers = NULL;
  for (size_t i = 0; i < req->header_count; i++) {
    curl_slist *nl = g_curl.slist_append(headers, req->headers[i]);
    if (nl != NULL)
      headers = nl;
  }

  resp_buf rb = {req->resp, 0, req->resp_cap};
  g_curl.easy_setopt(easy, CURLOPT_URL, req->url);
  g_curl.easy_setopt(easy, CURLOPT_HTTPHEADER, headers);
  g_curl.easy_setopt(easy, CURLOPT_WRITEFUNCTION, write_cb);
  g_curl.easy_setopt(easy, CURLOPT_WRITEDATA, &rb);
  g_curl.easy_setopt(easy, CURLOPT_FOLLOWLOCATION, 0L);
  g_curl.easy_setopt(easy, CURLOPT_NOSIGNAL, 1L);
  g_curl.easy_setopt(easy, CURLOPT_CONNECTTIMEOUT, 10L);
  g_curl.easy_setopt(easy, CURLOPT_TIMEOUT,
                     req->timeout_s > 0 ? req->timeout_s : 30L);
  g_curl.easy_setopt(easy, CURLOPT_SSL_VERIFYPEER, 1L);
  g_curl.easy_setopt(easy, CURLOPT_SSL_VERIFYHOST, 2L);
  if (req->ca_pem != NULL && req->ca_pem->ptr != NULL &&
      req->ca_pem->len > 0) {
    struct curl_blob blob = {(void *)req->ca_pem->ptr, req->ca_pem->len,
                             CURL_BLOB_COPY};
    g_curl.easy_setopt(easy, CURLOPT_CAINFO_BLOB, &blob);
  }

  if (strcmp(req->method, "GET") == 0) {
    g_curl.easy_setopt(easy, CURLOPT_HTTPGET, 1L);
  } else {
    g_curl.easy_setopt(easy, CURLOPT_POST, 1L);
    g_curl.easy_setopt(easy, CURLOPT_POSTFIELDS,
                       req->body ? (const char *)req->body : "");
    g_curl.easy_setopt(easy, CURLOPT_POSTFIELDSIZE, (long)req->body_len);
  }

  CURLcode rc = g_curl.easy_perform(easy);
  long code = 0;
  g_curl.easy_getinfo(easy, CURLINFO_RESPONSE_CODE, &code);
  g_curl.easy_cleanup(easy);
  g_curl.slist_free_all(headers);

  if (rc != CURLE_OK)
    return C2_ERR_IO;
  *req->status = code;
  *req->resp_len = rb.len;
  return C2_OK;
}
