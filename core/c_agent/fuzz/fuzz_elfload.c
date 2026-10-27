#include "util/elfload.h"

#include "fuzz_common.h"

#include <string.h>

/*
 * elfload_map parses an in-memory ELF64 image, maps its PT_LOAD segments and
 * applies dynamic relocations against the host's loaded libraries. The image is
 * attacker-controlled, so the Makefile builds this target with
 * -DELFLOAD_NO_EXEC: constructor and IFUNC/IRELATIVE execution is recorded
 * rather than called, and everything else (header and program-header parsing,
 * segment mapping, relocation writes, symbol lookup) runs for real.
 *
 * The property under test is memory safety: no image may make the mapper read
 * or write outside the image, the new mapping, or a caller buffer.
 */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  char err[160];

  elfload_module *m = elfload_map(data, size, err, sizeof(err));
  if (m == NULL)
    return 0;

  /* Exercise the exported-symbol lookup over the module's own dynamic symbol
   * table, including a name taken from the input. */
  static const char *const names[] = {"go", "bof_run", "bof_free", "dlsym",
                                      "x"};
  (void)elfload_sym(m, names[size % (sizeof(names) / sizeof(names[0]))]);

  char name[32];
  size_t n = size < sizeof(name) - 1 ? size : sizeof(name) - 1;
  if (n) {
    memcpy(name, data, n);
    name[n] = '\0';
    (void)elfload_sym(m, name);
  }

  elfload_free(m);
  return 0;
}
