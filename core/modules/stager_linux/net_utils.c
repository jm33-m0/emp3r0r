#include "net_utils.h"
#include "syscalls.h"
#include "utils.h"
#include <stdarg.h>

// Non-network functions removed.

unsigned short htons(unsigned short hostshort) {
  return (hostshort << 8) | (hostshort >> 8);
}

unsigned int htonl(unsigned int hostlong) {
  return ((hostlong & 0xFF000000) >> 24) | ((hostlong & 0x00FF0000) >> 8) |
         ((hostlong & 0x0000FF00) << 8) | ((hostlong & 0x000000FF) << 24);
}

int inet_aton(const char *cp, struct in_addr *inp) {
  unsigned int val = 0;
  int part = 0;
  int parts = 0;
  char c;

  while ((c = *cp++) != '\0') {
    if (c >= '0' && c <= '9') {
      part = part * 10 + (c - '0');
    } else if (c == '.') {
      if (part > 255)
        return 0;
      val = (val << 8) | part;
      part = 0;
      parts++;
    } else {
      return 0;
    }
  }
  if (part > 255 || parts != 3)
    return 0;
  val = (val << 8) | part;
  inp->s_addr = htonl(val);
  return 1;
}

int resolve_addr(const char *host, const char *port, struct sockaddr_in *out) {
  memset(out, 0, sizeof(*out));
  out->sin_family = AF_INET;

  int port_num = 0;
  const char *p = port;
  while (*p) {
    port_num = port_num * 10 + (*p - '0');
    p++;
  }
  out->sin_port = htons(port_num);

  if (inet_aton(host, &out->sin_addr) == 0)
    return -1;
  return 0;
}

// -----------------------------------------------------------------------------
// Socket Wrappers
// -----------------------------------------------------------------------------

int socket(int domain, int type, int protocol) {
  return (int)syscall3(SYS_socket, domain, type, protocol);
}

int connect(int sockfd, const struct sockaddr *addr, unsigned int addrlen) {
  return (int)syscall3(SYS_connect, sockfd, (long)addr, addrlen);
}

long send(int sockfd, const void *buf, size_t len, int flags) {
  return syscall6(SYS_sendto, sockfd, (long)buf, len, flags, 0, 0);
}

long recv(int sockfd, void *buf, size_t len, int flags) {
  return syscall6(SYS_recvfrom, sockfd, (long)buf, len, flags, 0, 0);
}

long sendto(int sockfd, const void *buf, size_t len, int flags,
            const struct sockaddr *dest_addr, unsigned int addrlen) {
  return syscall6(SYS_sendto, sockfd, (long)buf, len, flags, (long)dest_addr,
                  addrlen);
}

long recvfrom(int sockfd, void *buf, size_t len, int flags,
              struct sockaddr *src_addr, unsigned int *addrlen) {
  return syscall6(SYS_recvfrom, sockfd, (long)buf, len, flags, (long)src_addr,
                  (long)addrlen);
}

int setsockopt(int sockfd, int level, int optname, const void *optval,
               unsigned int optlen) {
  return (int)syscall5(SYS_setsockopt, sockfd, level, optname, (long)optval,
                       optlen);
}
