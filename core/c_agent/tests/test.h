#ifndef C2_TEST_H
#define C2_TEST_H

/*
 * Tiny assertion harness for the C agent unit tests. Each test is a standalone
 * translation unit with its own main(); there is no test framework dependency.
 */

#include <stdio.h>
#include <string.h>

static int g_c2_tests_checks;
static int g_c2_tests_failed;

static void c2_test_check(int ok, const char *expr, const char *file,
                          int line) {
  g_c2_tests_checks++;
  if (!ok) {
    g_c2_tests_failed++;
    fprintf(stderr, "  FAIL %s:%d: %s\n", file, line, expr);
  }
}

#define CHECK(cond) c2_test_check((cond) != 0, #cond, __FILE__, __LINE__)
#define CHECK_EQ_LONG(a, b)                                                    \
  c2_test_check((long)(a) == (long)(b), #a " == " #b, __FILE__, __LINE__)
#define CHECK_BYTES(a, b, n)                                                   \
  c2_test_check(memcmp((a), (b), (n)) == 0, #a " == " #b, __FILE__, __LINE__)

#define TEST_DONE()                                                            \
  do {                                                                         \
    printf("%s: %d checks, %d failed\n", __FILE__, g_c2_tests_checks,          \
           g_c2_tests_failed);                                                 \
    return g_c2_tests_failed ? 1 : 0;                                          \
  } while (0)

#endif /* C2_TEST_H */
