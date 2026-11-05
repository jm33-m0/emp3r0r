/* Test BOF: AT_RANDOM and getrandom come from the kernel RNG. The harness runs
 * this guest twice and compares the printed canary. */
#include <stdint.h>
#include <sys/auxv.h>
#include <sys/random.h>
#include <unistd.h>

int go(char *args, int len) {
  (void)args;
  (void)len;

  const unsigned char *rnd = (const unsigned char *)getauxval(AT_RANDOM);
  if (rnd == NULL)
    return 1;
  static const char hex[] = "0123456789abcdef";
  char text[33];
  for (int i = 0; i < 16; i++) {
    text[2 * i] = hex[rnd[i] >> 4];
    text[2 * i + 1] = hex[rnd[i] & 15];
  }
  text[32] = '\n';
  if (write(1, text, sizeof text) != (ssize_t)sizeof text)
    return 2;

  unsigned char extra[32];
  if (getrandom(extra, sizeof extra, 0) != (ssize_t)sizeof extra)
    return 3;
  return 0;
}
