/* Test BOF: socket syscalls. recvfrom has to write the source length back to
 * the guest, so the check uses the address the datagram came from. */
#include <arpa/inet.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

int go(char *args, int len) {
  (void)args;
  (void)len;
  int s = socket(AF_INET, SOCK_DGRAM, 0);
  if (s < 0)
    return 1;
  int one = 1;
  setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);

  struct sockaddr_in self;
  memset(&self, 0, sizeof self);
  self.sin_family = AF_INET;
  self.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  int bound = 0;
  for (int attempt = 0; attempt < 16 && !bound; attempt++) {
    unsigned port = (unsigned)(getpid() * 997 + attempt * 131) % 20000u;
    self.sin_port = htons((unsigned short)(40000u + port));
    if (bind(s, (struct sockaddr *)&self, sizeof self) == 0)
      bound = 1;
  }
  if (!bound)
    return 2;

  static const char msg[] = "ping";
  if (sendto(s, msg, sizeof msg, 0, (struct sockaddr *)&self, sizeof self) !=
      (ssize_t)sizeof msg)
    return 3;

  char buf[8];
  struct sockaddr_in from;
  socklen_t fromlen = sizeof from;
  ssize_t n =
      recvfrom(s, buf, sizeof buf, 0, (struct sockaddr *)&from, &fromlen);
  close(s);
  if (n != (ssize_t)sizeof msg)
    return 4;
  if (memcmp(buf, msg, sizeof msg) != 0)
    return 5;
  if (fromlen != sizeof from || from.sin_family != AF_INET ||
      from.sin_port != self.sin_port)
    return 6;
  return 0;
}
