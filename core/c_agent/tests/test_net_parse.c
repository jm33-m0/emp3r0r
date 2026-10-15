#include "util/net_utils.h"

#include "test.h"

int main(void) {
  CHECK_EQ_LONG(htons(0x1234), 0x3412);
  CHECK_EQ_LONG(htonl(0x11223344), 0x44332211);

  struct in_addr a;
  CHECK_EQ_LONG(inet_aton("127.0.0.1", &a), 1);
  CHECK_EQ_LONG(a.s_addr, htonl(0x7f000001u));
  CHECK_EQ_LONG(inet_aton("0.0.0.0", &a), 1);
  CHECK_EQ_LONG(a.s_addr, 0);
  CHECK_EQ_LONG(inet_aton("255.255.255.255", &a), 1);
  CHECK_EQ_LONG(a.s_addr, 0xffffffffu);

  CHECK_EQ_LONG(inet_aton("256.0.0.1", &a), 0);
  CHECK_EQ_LONG(inet_aton("1.2.3", &a), 0);
  CHECK_EQ_LONG(inet_aton("1.2.3.4.5", &a), 0);
  CHECK_EQ_LONG(inet_aton("a.b.c.d", &a), 0);
  CHECK_EQ_LONG(inet_aton("", &a), 0);

  struct sockaddr_in sa;
  CHECK_EQ_LONG(resolve_addr("10.0.0.1", "443", &sa), 0);
  CHECK_EQ_LONG(sa.sin_family, AF_INET);
  CHECK_EQ_LONG(sa.sin_port, htons(443));
  CHECK_EQ_LONG(sa.sin_addr.s_addr, htonl(0x0a000001u));
  CHECK_EQ_LONG(resolve_addr("not-an-ip", "80", &sa), -1);

  TEST_DONE();
}
