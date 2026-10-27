/*
 * transport_libssl.c — HTTP-poll transport over raw TCP and OpenSSL.
 *
 * The selected transport implements the whole wire stack itself: plain HTTP
 * URLs use the shared raw HTTP exchange, while https:// URLs add TLS with the
 * host's libssl/libcrypto loaded through dynload.h. It therefore behaves like
 * the libcurl transport without requiring libcurl: the same agent works
 * against a plain HTTP listener or a TLS-terminating one.
 *
 * Select with TRANSPORT=libssl. The raw HTTP helper is compiled only as a
 * support module for this transport.
 */

#define _GNU_SOURCE

#include "http_poll.h"
#include "http_wire.h"

#include "util/dynload.h"

#include <arpa/inet.h>
#include <limits.h>
#include <string.h>
#include <unistd.h>

/* ---- minimal OpenSSL ABI (stable symbols; no headers/link dependency) ---- */
typedef struct ssl_st SSL;
typedef struct ssl_ctx_st SSL_CTX;
typedef struct ssl_method_st SSL_METHOD;
typedef struct x509_st X509;
typedef struct x509_store_st X509_STORE;
typedef struct bio_st BIO;
typedef struct x509_verify_param_st X509_VERIFY_PARAM;

#define SSL_VERIFY_PEER 1
#define SSL_CTRL_SET_TLSEXT_HOSTNAME 55
#define SSL_ERROR_WANT_READ 2
#define SSL_ERROR_WANT_WRITE 3
#define SSL_ERROR_ZERO_RETURN 6

typedef SSL_METHOD *(*tls_client_method_fn)(void);
typedef SSL_CTX *(*ssl_ctx_new_fn)(const SSL_METHOD *);
typedef void (*ssl_ctx_free_fn)(SSL_CTX *);
typedef void (*ssl_ctx_set_verify_fn)(SSL_CTX *, int, int (*)(int, void *));
typedef int (*ssl_ctx_default_paths_fn)(SSL_CTX *);
typedef void (*ssl_ctx_set_cert_store_fn)(SSL_CTX *, X509_STORE *);
typedef SSL *(*ssl_new_fn)(SSL_CTX *);
typedef void (*ssl_free_fn)(SSL *);
typedef int (*ssl_set_fd_fn)(SSL *, int);
typedef int (*ssl_connect_fn)(SSL *);
typedef int (*ssl_read_fn)(SSL *, void *, int);
typedef int (*ssl_write_fn)(SSL *, const void *, int);
typedef int (*ssl_shutdown_fn)(SSL *);
typedef int (*ssl_get_error_fn)(const SSL *, int);
typedef long (*ssl_ctrl_fn)(SSL *, int, long, void *);
typedef X509_VERIFY_PARAM *(*ssl_get0_param_fn)(SSL *);
typedef int (*param_set1_host_fn)(X509_VERIFY_PARAM *, const char *, size_t);
typedef int (*param_set1_ip_fn)(X509_VERIFY_PARAM *, const char *);
typedef X509_STORE *(*x509_store_new_fn)(void);
typedef void (*x509_store_free_fn)(X509_STORE *);
typedef int (*x509_store_add_fn)(X509_STORE *, X509 *);
typedef void (*x509_free_fn)(X509 *);
typedef BIO *(*bio_new_mem_buf_fn)(const void *, int);
typedef void (*bio_free_fn)(BIO *);
typedef X509 *(*pem_read_x509_fn)(BIO *, X509 **, void *, void *);
typedef int (*openssl_init_ssl_fn)(unsigned long long, const void *);
typedef int (*ssl_library_init_fn)(void);

static struct {
  void *ssl_lib;
  void *crypto_lib;
  tls_client_method_fn tls_client_method;
  tls_client_method_fn sslv23_client_method;
  ssl_ctx_new_fn ctx_new;
  ssl_ctx_free_fn ctx_free;
  ssl_ctx_set_verify_fn ctx_set_verify;
  ssl_ctx_default_paths_fn ctx_default_paths;
  ssl_ctx_set_cert_store_fn ctx_set_cert_store;
  ssl_new_fn ssl_new;
  ssl_free_fn ssl_free;
  ssl_set_fd_fn ssl_set_fd;
  ssl_connect_fn ssl_connect;
  ssl_read_fn ssl_read;
  ssl_write_fn ssl_write;
  ssl_shutdown_fn ssl_shutdown;
  ssl_get_error_fn ssl_get_error;
  ssl_ctrl_fn ssl_ctrl;
  ssl_get0_param_fn get0_param;
  param_set1_host_fn set1_host;
  param_set1_ip_fn set1_ip;
  x509_store_new_fn store_new;
  x509_store_free_fn store_free;
  x509_store_add_fn store_add;
  x509_free_fn x509_free;
  bio_new_mem_buf_fn bio_new_mem;
  bio_free_fn bio_free;
  pem_read_x509_fn pem_read_x509;
  openssl_init_ssl_fn openssl_init_ssl;
  ssl_library_init_fn ssl_library_init;
  int ready;
  int failed;
} g_tls;

static int load_one(void *handle, const char *name, void **out) {
  *out = dynload_sym(dynload_hosted(), handle, name);
  return *out == NULL ? -1 : 0;
}

#define LOAD_REQ(handle, field, name)                                          \
  do {                                                                         \
    if (load_one((handle), (name), (void **)&g_tls.field) != 0)                \
      goto fail;                                                               \
  } while (0)
#define LOAD_OPT(handle, field, name)                                          \
  (void)load_one((handle), (name), (void **)&g_tls.field)

static int tls_load(void) {
  if (g_tls.ready)
    return 0;
  if (g_tls.failed)
    return -1;

  static const char *ssl_names[] = {"libssl.so.3",  "libssl.so.1.1",
                                    "libssl.so.10", "libssl.so.1.0.0",
                                    "libssl.so",    NULL};
  static const char *crypto_names[] = {"libcrypto.so.3",  "libcrypto.so.1.1",
                                       "libcrypto.so.10", "libcrypto.so.1.0.0",
                                       "libcrypto.so",    NULL};
  dynload *dl = dynload_hosted();
  for (size_t i = 0; ssl_names[i] != NULL && g_tls.ssl_lib == NULL; i++)
    g_tls.ssl_lib = dynload_open(dl, ssl_names[i], RTLD_LAZY | RTLD_LOCAL);
  for (size_t i = 0; crypto_names[i] != NULL && g_tls.crypto_lib == NULL; i++)
    g_tls.crypto_lib =
        dynload_open(dl, crypto_names[i], RTLD_LAZY | RTLD_LOCAL);
  if (g_tls.ssl_lib == NULL || g_tls.crypto_lib == NULL)
    goto fail;

  LOAD_OPT(g_tls.ssl_lib, tls_client_method, "TLS_client_method");
  LOAD_OPT(g_tls.ssl_lib, sslv23_client_method, "SSLv23_client_method");
  if (g_tls.tls_client_method == NULL && g_tls.sslv23_client_method == NULL)
    goto fail;
  LOAD_REQ(g_tls.ssl_lib, ctx_new, "SSL_CTX_new");
  LOAD_REQ(g_tls.ssl_lib, ctx_free, "SSL_CTX_free");
  LOAD_REQ(g_tls.ssl_lib, ctx_set_verify, "SSL_CTX_set_verify");
  LOAD_OPT(g_tls.ssl_lib, ctx_default_paths,
           "SSL_CTX_set_default_verify_paths");
  LOAD_OPT(g_tls.ssl_lib, ctx_set_cert_store, "SSL_CTX_set_cert_store");
  LOAD_REQ(g_tls.ssl_lib, ssl_new, "SSL_new");
  LOAD_REQ(g_tls.ssl_lib, ssl_free, "SSL_free");
  LOAD_REQ(g_tls.ssl_lib, ssl_set_fd, "SSL_set_fd");
  LOAD_REQ(g_tls.ssl_lib, ssl_connect, "SSL_connect");
  LOAD_REQ(g_tls.ssl_lib, ssl_read, "SSL_read");
  LOAD_REQ(g_tls.ssl_lib, ssl_write, "SSL_write");
  LOAD_REQ(g_tls.ssl_lib, ssl_shutdown, "SSL_shutdown");
  LOAD_REQ(g_tls.ssl_lib, ssl_get_error, "SSL_get_error");
  LOAD_OPT(g_tls.ssl_lib, ssl_ctrl, "SSL_ctrl");
  LOAD_OPT(g_tls.ssl_lib, get0_param, "SSL_get0_param");
  LOAD_OPT(g_tls.crypto_lib, set1_host, "X509_VERIFY_PARAM_set1_host");
  LOAD_OPT(g_tls.crypto_lib, set1_ip, "X509_VERIFY_PARAM_set1_ip_asc");
  LOAD_REQ(g_tls.crypto_lib, store_new, "X509_STORE_new");
  LOAD_REQ(g_tls.crypto_lib, store_free, "X509_STORE_free");
  LOAD_REQ(g_tls.crypto_lib, store_add, "X509_STORE_add_cert");
  LOAD_REQ(g_tls.crypto_lib, x509_free, "X509_free");
  LOAD_REQ(g_tls.crypto_lib, bio_new_mem, "BIO_new_mem_buf");
  LOAD_REQ(g_tls.crypto_lib, bio_free, "BIO_free");
  LOAD_REQ(g_tls.crypto_lib, pem_read_x509, "PEM_read_bio_X509");
  LOAD_OPT(g_tls.ssl_lib, openssl_init_ssl, "OPENSSL_init_ssl");
  LOAD_OPT(g_tls.ssl_lib, ssl_library_init, "SSL_library_init");
#undef LOAD_REQ
#undef LOAD_OPT

  if (g_tls.openssl_init_ssl != NULL)
    g_tls.openssl_init_ssl(0, NULL);
  else if (g_tls.ssl_library_init != NULL)
    (void)g_tls.ssl_library_init();
  g_tls.ready = 1;
  return 0;

fail:
  if (g_tls.ssl_lib != NULL)
    dynload_close(dl, g_tls.ssl_lib);
  if (g_tls.crypto_lib != NULL)
    dynload_close(dl, g_tls.crypto_lib);
  g_tls.ssl_lib = g_tls.crypto_lib = NULL;
  g_tls.failed = 1;
  return -1;
}

static int host_is_ip(const char *host) {
  unsigned char buf[16];
  return inet_pton(AF_INET, host, buf) == 1 ||
         inet_pton(AF_INET6, host, buf) == 1;
}

static int ssl_send_all(void *ctx, const uint8_t *buf, size_t len) {
  SSL *ssl = (SSL *)ctx;
  size_t off = 0;
  while (off < len) {
    size_t chunk = len - off;
    if (chunk > INT_MAX)
      chunk = INT_MAX;
    int n = g_tls.ssl_write(ssl, buf + off, (int)chunk);
    if (n <= 0) {
      int err = g_tls.ssl_get_error(ssl, n);
      if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE)
        continue;
      return -1;
    }
    off += (size_t)n;
  }
  return 0;
}

static int ssl_recv_some(void *ctx, uint8_t *buf, size_t cap) {
  SSL *ssl = (SSL *)ctx;
  if (cap > INT_MAX)
    cap = INT_MAX;
  for (;;) {
    int n = g_tls.ssl_read(ssl, buf, (int)cap);
    if (n > 0)
      return n;
    int err = g_tls.ssl_get_error(ssl, n);
    if (err == SSL_ERROR_ZERO_RETURN)
      return 0;
    if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE)
      continue;
    return -1;
  }
}

static int tls_verify_config(SSL_CTX *ctx, SSL *ssl, const c2_str *ca_pem,
                             const char *host) {
  g_tls.ctx_set_verify(ctx, SSL_VERIFY_PEER, NULL);

  if (ca_pem != NULL && ca_pem->ptr != NULL && ca_pem->len > 0) {
    if (g_tls.ctx_set_cert_store == NULL || g_tls.store_new == NULL ||
        g_tls.store_add == NULL || g_tls.bio_new_mem == NULL ||
        g_tls.pem_read_x509 == NULL || g_tls.x509_free == NULL ||
        g_tls.bio_free == NULL || g_tls.store_free == NULL)
      return -1;
    X509_STORE *store = g_tls.store_new();
    if (store == NULL)
      return -1;
    BIO *bio = g_tls.bio_new_mem(ca_pem->ptr, (int)ca_pem->len);
    if (bio == NULL) {
      g_tls.store_free(store);
      return -1;
    }
    X509 *cert = g_tls.pem_read_x509(bio, NULL, NULL, NULL);
    g_tls.bio_free(bio);
    if (cert == NULL) {
      g_tls.store_free(store);
      return -1;
    }
    int ok = g_tls.store_add(store, cert);
    g_tls.x509_free(cert);
    if (ok != 1) {
      g_tls.store_free(store);
      return -1;
    }
    g_tls.ctx_set_cert_store(ctx, store);
  } else if (g_tls.ctx_default_paths == NULL ||
             g_tls.ctx_default_paths(ctx) != 1) {
    return -1;
  }

  if (g_tls.get0_param != NULL) {
    X509_VERIFY_PARAM *param = g_tls.get0_param(ssl);
    if (param != NULL) {
      if (host_is_ip(host)) {
        if (g_tls.set1_ip == NULL || g_tls.set1_ip(param, host) != 1)
          return -1;
      } else if (g_tls.set1_host == NULL ||
                 g_tls.set1_host(param, host, 0) != 1) {
        return -1;
      }
    }
  }
  return 0;
}

static c2_status hp_http_ssl_perform(const hp_http_request *req,
                                     const char *host, const char *port,
                                     const char *path, const char *authority) {
  if (tls_load() != 0)
    return C2_ERR_UNSUPPORTED;

  int fd =
      hp_http_tcp_connect(host, port, (int)req->timeout_s, req->doh_server);
  if (fd < 0)
    return C2_ERR_IO;

  SSL_METHOD *method = g_tls.tls_client_method != NULL
                           ? g_tls.tls_client_method()
                           : g_tls.sslv23_client_method();
  SSL_CTX *ctx = method != NULL ? g_tls.ctx_new(method) : NULL;
  SSL *ssl = ctx != NULL ? g_tls.ssl_new(ctx) : NULL;
  if (ssl == NULL) {
    if (ctx != NULL)
      g_tls.ctx_free(ctx);
    close(fd);
    return C2_ERR_UNSUPPORTED;
  }

  if (tls_verify_config(ctx, ssl, req->ca_pem, host) != 0) {
    g_tls.ssl_free(ssl);
    g_tls.ctx_free(ctx);
    close(fd);
    return C2_ERR_AUTH;
  }

  /* SNI is a DNS name, not an IP literal. */
  if (!host_is_ip(host) && g_tls.ssl_ctrl != NULL)
    (void)g_tls.ssl_ctrl(ssl, SSL_CTRL_SET_TLSEXT_HOSTNAME, 0, (void *)host);

  if (g_tls.ssl_set_fd(ssl, fd) != 1 || g_tls.ssl_connect(ssl) != 1) {
    g_tls.ssl_free(ssl);
    g_tls.ctx_free(ctx);
    close(fd);
    return C2_ERR_IO;
  }

  hp_http_io io = {ssl, ssl_send_all, ssl_recv_some};
  c2_status st = hp_http_exchange(req, path, authority, &io);
  (void)g_tls.ssl_shutdown(ssl);
  g_tls.ssl_free(ssl);
  g_tls.ctx_free(ctx);
  close(fd);
  return st;
}

c2_status hp_http_perform(const hp_http_request *req) {
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
  if (!tls)
    return hp_http_raw_perform(req);
  return hp_http_ssl_perform(req, host, port, path, authority);
}

const char *c2_transport_name(void) {
  return "libssl";
}
