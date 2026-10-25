#ifndef UTIL_DOH_H
#define UTIL_DOH_H

/*
 * util/doh.h — optional DNS-over-HTTPS resolution for transports that own
 * their socket (http_raw, libssl). libcurl has its own resolver and uses
 * CURLOPT_DOH_URL directly.
 *
 * The DoH client is loaded only when the agent config supplies a resolver URL;
 * without one the transports keep using libc getaddrinfo().
 */

#include "common.h"

#include <sys/socket.h>

#ifdef __cplusplus
extern "C" {
#endif

#define C2_DOH_MAX_ADDRS 16

typedef struct {
  struct sockaddr_storage addr;
  socklen_t addr_len;
  int family;
  int socktype;
  int protocol;
} c2_doh_addr;

typedef struct {
  c2_doh_addr addrs[C2_DOH_MAX_ADDRS];
  size_t count;
} c2_doh_addrs;

/*
 * Resolve host:port over DoH. Returns 0 and fills out, or -1 on failure.
 * A numeric host is accepted directly without a network query.
 */
int c2_doh_resolve(const c2_str *doh_url, const char *host, const char *port,
                   int socktype, c2_doh_addrs *out);

#ifdef __cplusplus
}
#endif

#endif /* UTIL_DOH_H */
