#include "agent_args.h"

#include "fuzz_common.h"

#include <stdlib.h>
#include <string.h>

/*
 * The agent turns a wire command slice into paths and flag values with these
 * helpers. They are pure and side-effect free, so an arbitrary token list and
 * destination capacity can be tested directly; ASan catches any write past the
 * caller's buffer, and the terminator check catches a missing NUL.
 */

#define MAX_TOKENS 16

static void check_terminated(const char *buf, size_t cap) {
  if (cap == 0)
    return;
  if (memchr(buf, '\0', cap) == NULL)
    c2_fuzz_fail("command argument was not NUL-terminated");
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  c2_str items[MAX_TOKENS];
  size_t count = 0;

  /* Split on newlines; the bytes inside a token remain arbitrary (including
   * embedded NULs), matching a c2_str slice. */
  const uint8_t *p = data;
  size_t remaining = size;
  while (remaining > 0 && count < MAX_TOKENS) {
    const uint8_t *nl = (const uint8_t *)memchr(p, '\n', remaining);
    size_t len = nl ? (size_t)(nl - p) : remaining;
    items[count++] = c2_str_of((const char *)p, len);
    if (nl == NULL)
      break;
    remaining -= len + 1;
    p = nl + 1;
  }
  c2_str_list cmd = {items, count, MAX_TOKENS};

  size_t cap = 1 + (size ? size % 96 : 0);
  char *out = (char *)malloc(cap);
  if (out == NULL)
    return 0;

  for (size_t start = 0; start <= count + 1; start++) {
    c2_cmd_pick_path(&cmd, start, "default", out, cap);
    check_terminated(out, cap);
    c2_cmd_pick_path(&cmd, start, NULL, out, cap);
    check_terminated(out, cap);
  }

  for (size_t n = 0; n <= count + 1; n++) {
    c2_cmd_argn(&cmd, n, out, cap);
    check_terminated(out, cap);
  }

  static const char *const flags[] = {"--dst",
                                      "--path",
                                      "--mod_name",
                                      "--type",
                                      "--file_to_download",
                                      "--checksum",
                                      "--invocation",
                                      "--name"};
  for (size_t i = 0; i < sizeof(flags) / sizeof(flags[0]); i++) {
    c2_cmd_pick_flag(&cmd, flags[i], out, cap);
    check_terminated(out, cap);
  }

  free(out);
  return 0;
}
