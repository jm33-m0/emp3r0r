#include "dynload.h"

#include "test.h"

/* Exercises the real ELF resolution path against the running process's libc,
 * so a broken /proc/self/maps parse or hash-table walk fails here. */

int main(void) {
  unsigned long libc = dynload_find_libc();
  CHECK(libc != 0);
  if (libc == 0)
    TEST_DONE();

  CHECK(dynload_resolve_module((void *)libc, "malloc") != NULL);
  CHECK(dynload_resolve_module((void *)libc, "free") != NULL);
  CHECK(dynload_resolve_module((void *)libc, "no_such_symbol_xyz") == NULL);

  dynload *dl = dynload_hosted();
  CHECK(dynload_resolve(dl) == 0);
  CHECK(dynload_resolve(dl) == 0); /* idempotent */

  void *h = dynload_open(dl, "libc.so.6", RTLD_NOW | RTLD_LOCAL);
  CHECK(h != NULL);
  CHECK(dynload_sym(dl, h, "malloc") != NULL);
  CHECK(dynload_sym(dl, h, "no_such_symbol_xyz") == NULL);
  CHECK(dynload_close(dl, h) == 0);

  dynload_reset(dl);
  CHECK(dl->open == NULL && dl->sym == NULL && dl->close == NULL);
  CHECK(dynload_resolve(dl) == 0);

  TEST_DONE();
}
