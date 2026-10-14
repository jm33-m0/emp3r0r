#ifndef C2_HTTP_CLIENT_H
#define C2_HTTP_CLIENT_H

/*
 * c2_http_client.h — HTTP(S) client provider contract.
 *
 * The http_poll transport is just a state machine over request/response HTTP;
 * the TLS stack (and how requests are actually sent) lives behind this small
 * interface. Exactly one provider is compiled in, selected with
 * `HTTP=<name>` (see the Makefile): src/transport/c2_http_client_<name>.c.
 *
 *   libcurl (default): dlopen the system libcurl; TLS handled by libcurl.
 *   (add c2_http_client_<name>.c to plug in mbedTLS, raw sockets, ...)
 *
 * A provider only has to perform one request/response; it never sees the C2
 * protocol and knows nothing about CBOR or SecureConn.
 */

#include "c2_common.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct c2_http_request {
  const char *url;              /* fully resolved, e.g. https://host/path */
  const char *method;           /* "GET" or "POST" */
  const char *const *headers;   /* "Name: Value" lines, borrowed */
  size_t header_count;
  const uint8_t *body;          /* NULL for GET */
  size_t body_len;
  uint8_t *resp;                /* response body is copied here */
  size_t resp_cap;
  size_t *resp_len;             /* set to the number of bytes written */
  long *status;                 /* set to the HTTP status code */
  long timeout_s;               /* whole-request timeout */
  const c2_str *ca_pem;         /* PEM CA to verify against; may be NULL */
} c2_http_request;

/*
 * Perform exactly one request. Returns C2_OK when an HTTP response was
 * received (even a non-2xx one; the caller inspects *status), C2_ERR_IO on a
 * transport failure, C2_ERR_UNSUPPORTED when the provider is unavailable and
 * C2_ERR_NOMEM when the response does not fit resp_cap.
 */
c2_status c2_http_client_perform(const c2_http_request *req);

#ifdef __cplusplus
}
#endif

#endif /* C2_HTTP_CLIENT_H */
