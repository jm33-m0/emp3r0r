/* Test BOF: the guest clock must reach the host through the syscall gate. */
#include <time.h>

int go(char *args, int len) {
  (void)args;
  (void)len;
  return time(0) > 0 ? 0 : 7;
}
