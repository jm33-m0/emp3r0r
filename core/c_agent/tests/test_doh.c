/* Numeric C2 addresses must bypass the DoH network query; this exercises the
 * resolver's address construction without depending on external DNS. */

#include "util/doh.h"

#include "test.h"

#include <netinet/in.h>

int main(void) {
  c2_str doh = c2_str_lit("https://1.1.1.1/dns-query");
  c2_doh_addrs out;
  CHECK(c2_doh_resolve(&doh, "127.0.0.1", "443", SOCK_STREAM, &out) == 0);
  CHECK(out.count == 1);
  if (out.count == 1) {
    CHECK(out.addrs[0].family == AF_INET);
    CHECK(out.addrs[0].socktype == SOCK_STREAM);
    const struct sockaddr_in *sin =
        (const struct sockaddr_in *)&out.addrs[0].addr;
    CHECK(sin->sin_port == htons(443));
  }
  CHECK(c2_doh_resolve(&doh, "::1", "443", SOCK_STREAM, &out) == 0);
  CHECK(out.count == 1 && out.addrs[0].family == AF_INET6);
  CHECK(c2_doh_resolve(&doh, "", "443", SOCK_STREAM, &out) != 0);
  TEST_DONE();
}
