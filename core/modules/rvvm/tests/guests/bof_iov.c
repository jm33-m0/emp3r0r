/* Test BOF: zero-length iovecs are legal and carry no address. musl passes one
 * with a NULL iov_base whenever a stdio buffer has nothing pending, so the gate
 * has to skip it instead of rejecting the whole call. */
#include <fcntl.h>
#include <stddef.h>
#include <sys/uio.h>
#include <unistd.h>

int go(char *args, int len) {
  (void)args;
  (void)len;
  static const char msg[] = "iov";
  struct iovec iov[2];
  iov[0].iov_base = NULL;
  iov[0].iov_len = 0;
  iov[1].iov_base = (void *)msg;
  iov[1].iov_len = sizeof msg - 1;
  if (writev(1, iov, 2) != (ssize_t)(sizeof msg - 1))
    return 1;

  int fd = open("/dev/zero", O_RDONLY);
  if (fd < 0)
    return 2;
  char buf[4];
  iov[1].iov_base = buf;
  iov[1].iov_len = sizeof buf;
  ssize_t n = readv(fd, iov, 2);
  close(fd);
  if (n != (ssize_t)sizeof buf)
    return 3;
  for (size_t i = 0; i < sizeof buf; i++) {
    if (buf[i] != 0)
      return 4;
  }
  return 0;
}
