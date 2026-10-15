#include "util/strings.h"

#include "test.h"

/* The point of strings.c is that it must behave exactly like libc for the
 * subset the payloads use, including overlapping copies. */

int main(void) {
  char buf[32];
  char overlap[16];

  CHECK_EQ_LONG(strlen(""), 0);
  CHECK_EQ_LONG(strlen("abc"), 3);

  CHECK_EQ_LONG(strcmp("", ""), 0);
  CHECK_EQ_LONG(strcmp("abc", "abc"), 0);
  CHECK(strcmp("abc", "abd") < 0);
  CHECK(strcmp("abd", "abc") > 0);
  CHECK(strcmp("abc", "abcd") < 0);

  memset(buf, 'x', sizeof(buf));
  CHECK(buf[0] == 'x' && buf[31] == 'x');
  memset(buf, 0, 4);
  CHECK(buf[0] == 0 && buf[4] == 'x');

  memcpy(buf, "hello", 6);
  CHECK(strcmp(buf, "hello") == 0);

  /* Forward and backward overlap. This is a deliberate extension over the C
   * standard (memcpy overlap is UB); the freestanding stager relies on it as a
   * general-purpose copy. The diagnostic is disabled because we are testing
   * exactly that extension, not calling memcpy by accident. */
#if defined(__GNUC__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wrestrict"
#endif
  memcpy(overlap, "abcdefgh", 8);
  memcpy(overlap + 2, overlap, 6);
  CHECK(memcmp(overlap, "ababcdef", 8) == 0);

  memcpy(overlap, "abcdefgh", 8);
  memcpy(overlap, overlap + 2, 6);
  CHECK(memcmp(overlap, "cdefghgh", 8) == 0);
#if defined(__GNUC__)
#pragma GCC diagnostic pop
#endif

  /* No-op and zero-length copies must not touch the destination. */
  memcpy(buf, buf, 6);
  CHECK(strcmp(buf, "hello") == 0);
  memcpy(buf, "zzz", 0);
  CHECK(strcmp(buf, "hello") == 0);

  CHECK(strstr("hello world", "world") != NULL);
  CHECK(strstr("hello world", "world") == &"hello world"[6]);
  CHECK(strstr("hello", "") == &"hello"[0]);
  CHECK(strstr("hello", "x") == NULL);
  CHECK(strstr("", "x") == NULL);
  CHECK(strstr("aab", "ab") != NULL);

  TEST_DONE();
}
