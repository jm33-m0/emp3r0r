#ifndef NET_UTILS_H
#define NET_UTILS_H

#include <stddef.h>
#include <stdint.h>

// Socket
#define AF_INET 2
#define SOCK_STREAM 1
#define SOCK_DGRAM 2
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17

// Socket options
#define SOL_SOCKET 1
#define SO_RCVTIMEO 20

struct sockaddr {
  unsigned short sa_family;
  char sa_data[14];
};

struct in_addr {
  unsigned int s_addr;
};

struct sockaddr_in {
  unsigned short sin_family;
  unsigned short sin_port;
  struct in_addr sin_addr;
  unsigned char sin_zero[8];
};

struct timeval {
  long tv_sec;
  long tv_usec;
};

// Helper for IP parsing
int inet_aton(const char *cp, struct in_addr *inp);
unsigned short htons(unsigned short hostshort);
unsigned int htonl(unsigned int hostlong);

// Resolve host:port into an IPv4 sockaddr_in (returns 0 on success).
int resolve_addr(const char *host, const char *port, struct sockaddr_in *out);

// Socket wrappers
int socket(int domain, int type, int protocol);
int connect(int sockfd, const struct sockaddr *addr, unsigned int addrlen);
long send(int sockfd, const void *buf, size_t len, int flags);
long recv(int sockfd, void *buf, size_t len, int flags);
long sendto(int sockfd, const void *buf, size_t len, int flags,
            const struct sockaddr *dest_addr, unsigned int addrlen);
long recvfrom(int sockfd, void *buf, size_t len, int flags,
              struct sockaddr *src_addr, unsigned int *addrlen);
int setsockopt(int sockfd, int level, int optname, const void *optval,
               unsigned int optlen);

#endif
