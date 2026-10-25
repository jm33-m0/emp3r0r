#ifndef C2_HTTP_WIRE_H
#define C2_HTTP_WIRE_H

/*
 * Shared HTTP/1.1 wire helpers for transports that implement their own TCP or
 * TLS stack. A transport supplies hp_http_io; the common code builds the
 * request, reads the response, and decodes Content-Length/chunked bodies.
 */

#include "http_poll.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct hp_http_io {
  void *ctx;
  /* Write the whole buffer. Returns 0 on success, -1 on failure. */
  int (*send_all)(void *ctx, const uint8_t *buf, size_t len);
  /* Read up to cap bytes. Returns >0 bytes, 0 at EOF, -1 on failure. */
  int (*recv_some)(void *ctx, uint8_t *buf, size_t cap);
} hp_http_io;

/* Parse http[s]://host[:port][/path]. The scheme is returned in *tls. */
int hp_http_parse_url(const char *url, char *host, size_t host_cap, char *port,
                      size_t port_cap, char *path, size_t path_cap,
                      char *authority, size_t auth_cap, int *tls);

/* Connect a TCP socket to host:port, returning the fd or -1. */
int hp_http_tcp_connect(const char *host, const char *port, int timeout_s,
                        const c2_str *doh_url);

/* Perform one request/response over an already connected hp_http_io. */
c2_status hp_http_exchange(const hp_http_request *req, const char *path,
                           const char *authority, const hp_http_io *io);

/* Plain-HTTP implementation, reused by the libssl transport for http:// URLs. */
c2_status hp_http_raw_perform(const hp_http_request *req);

#ifdef __cplusplus
}
#endif

#endif /* C2_HTTP_WIRE_H */
