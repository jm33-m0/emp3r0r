#ifndef C2_HTTP_POLL_H
#define C2_HTTP_POLL_H

/*
 * One request/response exchange used by the shared http_poll state machine.
 *
 * A transport implements hp_http_perform(). It must return C2_OK once an HTTP
 * response was received (even a non-2xx one; the caller checks *status), and
 * C2_ERR_IO/UNSUPPORTED/NOMEM on transport failure. The transport owns the
 * wire protocol and any TLS/library loading.
 */

#include "common.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct hp_http_request {
  const char *url;            /* fully resolved, e.g. http://host:port/path */
  const char *method;         /* "GET" or "POST" */
  const char *const *headers; /* "Name: Value" lines, borrowed */
  size_t header_count;
  const uint8_t *body; /* NULL for GET */
  size_t body_len;
  uint8_t *resp; /* response body is copied here */
  size_t resp_cap;
  size_t *resp_len;         /* set to the number of bytes written */
  long *status;             /* set to the HTTP status code */
  long timeout_s;           /* whole-request timeout */
  const c2_str *ca_pem;     /* PEM CA to verify against; may be NULL */
  const c2_str *doh_server; /* DoH resolver URL; may be NULL/empty */
} hp_http_request;

c2_status hp_http_perform(const hp_http_request *req);

#ifdef __cplusplus
}
#endif

#endif /* C2_HTTP_POLL_H */
