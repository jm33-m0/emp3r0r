/*
 * test_stager_iface.c — the agent side of the same-process stager handshake.
 *
 * The stager publishes its mask entry point in the GS state block. The checks
 * run in a forked child that installs a fabricated block and then exits with
 * _exit: changing the GS base after libc initialization must not be unwound
 * through the parent's TLS destructors.
 */

#define _GNU_SOURCE

#include "stager_iface.h"

#include "test.h"

#include <stdint.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#define TEST_ARCH_SET_GS 0x1001

static unsigned g_last_seconds;
static uintptr_t g_last_probe;
static int g_calls;

static int mock_mask(unsigned seconds, uintptr_t probe) {
  g_last_seconds = seconds;
  g_last_probe = probe;
  g_calls++;
  return 0;
}

static int run_case(int valid) {
  pid_t pid = fork();
  if (pid < 0)
    return -1;
  if (pid == 0) {
    if (!valid) {
      (void)syscall(SYS_arch_prctl, TEST_ARCH_SET_GS, (uintptr_t)0);
      if (c2_stager_mask_bind() != -1 || c2_stager_mask_available() != 0 ||
          c2_stager_masked_sleep(1) != -1 || g_calls != 0)
        _exit(1);
      _exit(0);
    }

    static struct c2_stager_public pub;
    memset(&pub, 0, sizeof(pub));
    pub.self = &pub;
    pub.abi_magic = C2_STAGER_ABI_MAGIC;
    pub.abi_version = C2_STAGER_ABI_VERSION;
    pub.mask_fn = mock_mask;
    if (syscall(SYS_arch_prctl, TEST_ARCH_SET_GS, (uintptr_t)&pub) != 0)
      _exit(2);
    if (c2_stager_mask_bind() != 0 || c2_stager_mask_available() != 1 ||
        c2_stager_mask_bind() != 0)
      _exit(3);
    if (c2_stager_masked_sleep(7) != 0 || g_calls != 1 ||
        g_last_seconds != 7 || g_last_probe == 0)
      _exit(4);
    _exit(0);
  }

  int status = 0;
  if (waitpid(pid, &status, 0) != pid || !WIFEXITED(status))
    return -1;
  return WEXITSTATUS(status);
}

int main(void) {
#if !defined(__x86_64__)
  /* The stager publishes through the x86_64 GS base. */
  TEST_DONE();
#else
  CHECK_EQ_LONG(run_case(0), 0);
  CHECK_EQ_LONG(run_case(1), 0);
  TEST_DONE();
#endif
}
