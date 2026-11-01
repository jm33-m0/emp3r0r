/* Test BOF: fcntl lock commands carry a guest struct flock pointer, which the
 * syscall gate has to translate before the host sees it. */
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

int go(char *args, int len) {
  (void)args;
  (void)len;
  int fd = open("/dev/null", O_RDONLY);
  if (fd < 0)
    return 1;
  struct flock fl;
  memset(&fl, 0, sizeof fl);
  fl.l_type = F_RDLCK;
  fl.l_whence = SEEK_SET;
  if (fcntl(fd, F_SETLK, &fl) != 0) {
    close(fd);
    return 2;
  }
  if (fcntl(fd, F_GETLK, &fl) != 0) {
    close(fd);
    return 3;
  }
  fl.l_type = F_UNLCK;
  if (fcntl(fd, F_SETLK, &fl) != 0) {
    close(fd);
    return 4;
  }
  close(fd);
  return 0;
}
