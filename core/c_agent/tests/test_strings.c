#include "util/strings.h"

#include "test.h"

/* The point of strings.c is that it must behave exactly like libc for the
 * subset the payloads use, including overlapping copies. Call through a
 * pointer so the compiler cannot replace the test with an optimized libc
 * builtin whose overlap semantics differ between toolchains. */
typedef void *(*copy_fn)(void *dest, const void *src, size_t n);

static void test_copy(void *dest, const void *src, size_t n) {
  volatile copy_fn copy = memcpy;
  copy(dest, src, n);
}

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
   * general-purpose copy. */
  test_copy(overlap, "abcdefgh", 8);
  test_copy(overlap + 2, overlap, 6);
  CHECK(memcmp(overlap, "ababcdef", 8) == 0);

  test_copy(overlap, "abcdefgh", 8);
  test_copy(overlap, overlap + 2, 6);
  CHECK(memcmp(overlap, "cdefghgh", 8) == 0);

  /* No-op and zero-length copies must not touch the destination. */
  test_copy(buf, buf, 6);
  CHECK(strcmp(buf, "hello") == 0);
  test_copy(buf, "zzz", 0);
  CHECK(strcmp(buf, "hello") == 0);

  CHECK(strstr("hello world", "world") != NULL);
  CHECK(strstr("hello world", "world") == &"hello world"[6]);
  CHECK(strstr("hello", "") == &"hello"[0]);
  CHECK(strstr("hello", "x") == NULL);
  CHECK(strstr("", "x") == NULL);
  CHECK(strstr("aab", "ab") != NULL);

  TEST_DONE();
}
