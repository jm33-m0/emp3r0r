/*
 * ifunc_bof.c — BOF fixture whose libc calls must go through real symbols.
 *
 * memcpy, memset, strlen, strchr, strrchr, strcmp and memcmp are GNU IFUNC
 * symbols on glibc: the dynamic symbol points at a resolver, not at the
 * implementation. A loader that builds its trampoline from the resolver address
 * makes every one of these calls return an address instead of doing its work,
 * and a BOF that only uses them on constants would never notice because the
 * compiler inlines those.
 *
 * The pointers and lengths below are volatile so the calls are real.
 */

#include <string.h>

extern void BeaconPrintf(int type, const char *fmt, ...);

void go(char *args, int len) {
  (void)args;
  (void)len;

  const char *volatile text = "ab:cd:ef";
  volatile size_t take = 5;
  char buf[16];

  char *last = strrchr(text, ':');
  char *first = strchr(text, ':');
  size_t n = strlen(text);
  memcpy(buf, (const void *)text, take);
  buf[take] = '\0';

  int ok = last == text + 5 && first == text + 2 && n == 8 &&
           strcmp(buf, "ab:cd") == 0 && memcmp(text, "ab:c", 4) == 0;

  char *filled = memset(buf + take, '7', 2);
  filled[2] = '\0';
  ok = ok && filled == buf + take && strcmp(buf, "ab:cd77") == 0;

  BeaconPrintf(0, ok ? "ifunc ok" : "ifunc broken");
}
