/* Test BOF: the syscall gate rejects untranslatable pointers and keeps guest
 * descriptors close-on-exec. */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sched.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>

#define BAD_ADDR ((void *)(uintptr_t)0xdeadbeefu)

int go(char *args, int len) {
  (void)args;
  (void)len;

  /* A cpu_set outside guest RAM must fail before the host sees it. */
  cpu_set_t set;
  if (sched_getaffinity(0, sizeof set, BAD_ADDR) != -1 || errno != EFAULT)
    return 1;
  cpu_set_t *volatile no_set = NULL;
  if (sched_getaffinity(0, sizeof set, no_set) != -1 || errno != EFAULT)
    return 11;
  if (sched_getaffinity(0, sizeof set, &set) != 0)
    return 2;
  /* The guest may only ask about itself. */
  pid_t other = getpid() == 1 ? 2 : 1;
  if (sched_getaffinity(other, sizeof set, &set) != -1 || errno != EINVAL)
    return 3;

  /* Descriptors opened for the guest must not survive exec. */
  int fd = open("/dev/null", O_RDONLY);
  if (fd < 0)
    return 4;
  if (fcntl(fd, F_GETFD) != FD_CLOEXEC)
    return 5;
  close(fd);

  /* recvmsg must reject an untranslatable address instead of handing the host
   * a null buffer with a non-zero length. */
  int s = socket(AF_INET, SOCK_DGRAM, 0);
  if (s < 0)
    return 6;
  if (fcntl(s, F_GETFD) != FD_CLOEXEC)
    return 7;
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
    return 8;

  char byte;
  struct iovec iov;
  iov.iov_base = &byte;
  iov.iov_len = sizeof byte;
  struct msghdr msg;
  memset(&msg, 0, sizeof msg);
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;
  msg.msg_name = BAD_ADDR;
  msg.msg_namelen = sizeof(struct sockaddr_in);
  if (recvmsg(s, &msg, 0) != -1 || errno != EFAULT)
    return 9;
  msg.msg_name = NULL;
  msg.msg_namelen = 0;
  msg.msg_control = BAD_ADDR;
  msg.msg_controllen = 16;
  if (recvmsg(s, &msg, 0) != -1 || errno != EFAULT)
    return 10;
  close(s);
  return 0;
}
