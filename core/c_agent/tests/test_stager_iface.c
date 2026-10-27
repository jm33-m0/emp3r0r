/*
 * test_stager_iface.c — the agent side of the same-process stager handshake.
 *
 * The stager publishes its mask entry point in the GS state block. The checks
 * run in a forked child that installs a fabricated block, restores the original
 * GS base, and then exits normally: changing the GS base after libc
 * initialization must not be unwound through the parent's TLS destructors.
 */

#define _GNU_SOURCE

#include "stager_iface.h"

#include "test.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#define TEST_ARCH_SET_GS 0x1001
#define TEST_ARCH_GET_GS 0x1003

static unsigned g_last_seconds;
static uintptr_t g_last_probe;
static int g_calls;

static int mock_mask(unsigned seconds, uintptr_t probe) {
  g_last_seconds = seconds;
  g_last_probe = probe;
  g_calls++;
  return 0;
}

/* Restore the parent's TLS before a normal exit so gcov's atexit handlers run
 * on the original GS base, not the fake stager block. */
static void child_exit(uintptr_t orig_gs, int code) {
  (void)syscall(SYS_arch_prctl, TEST_ARCH_SET_GS, orig_gs);
  exit(code);
}

enum bind_case {
  BIND_NO_GS,
  BIND_VALID,
  BIND_BAD_MAGIC,
  BIND_BAD_VERSION,
  BIND_NULL_MASK,
  BIND_BAD_SELF,
};

static int run_case(enum bind_case tc) {
  pid_t pid = fork();
  if (pid < 0)
    return -1;
  if (pid == 0) {
    uintptr_t orig_gs = 0;
    if (syscall(SYS_arch_prctl, TEST_ARCH_GET_GS, &orig_gs) != 0)
      _exit(7);
    if (tc == BIND_NO_GS) {
      (void)syscall(SYS_arch_prctl, TEST_ARCH_SET_GS, (uintptr_t)0);
      if (c2_stager_mask_bind() != -1 || c2_stager_mask_available() != 0 ||
          c2_stager_masked_sleep(1) != -1 || g_calls != 0)
        child_exit(orig_gs, 1);
      child_exit(orig_gs, 0);
    }

    static struct c2_stager_public pub;
    memset(&pub, 0, sizeof(pub));
    pub.self = &pub;
    pub.abi_magic = C2_STAGER_ABI_MAGIC;
    pub.abi_version = C2_STAGER_ABI_VERSION;
    pub.mask_fn = mock_mask;
    switch (tc) {
    case BIND_BAD_MAGIC:
      pub.abi_magic = 0;
      break;
    case BIND_BAD_VERSION:
      pub.abi_version++;
      break;
    case BIND_NULL_MASK:
      pub.mask_fn = NULL;
      break;
    case BIND_BAD_SELF:
      pub.self = NULL;
      break;
    default:
      break;
    }
    if (syscall(SYS_arch_prctl, TEST_ARCH_SET_GS, (uintptr_t)&pub) != 0)
      _exit(2);
    if (tc != BIND_VALID) {
      if (c2_stager_mask_bind() != -1 || c2_stager_mask_available() != 0 ||
          c2_stager_masked_sleep(1) != -1 || g_calls != 0)
        child_exit(orig_gs, 5);
      child_exit(orig_gs, 0);
    }
    if (c2_stager_mask_bind() != 0 || c2_stager_mask_available() != 1 ||
        c2_stager_mask_bind() != 0)
      child_exit(orig_gs, 3);
    if (c2_stager_masked_sleep(7) != 0 || g_calls != 1 || g_last_seconds != 7 ||
        g_last_probe == 0)
      child_exit(orig_gs, 4);
    /* A zero duration is normalised to one second, never a busy spin. */
    if (c2_stager_masked_sleep(0) != 0 || g_calls != 2 || g_last_seconds != 1)
      child_exit(orig_gs, 6);
    child_exit(orig_gs, 0);
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
  CHECK_EQ_LONG(run_case(BIND_NO_GS), 0);
  CHECK_EQ_LONG(run_case(BIND_VALID), 0);
  CHECK_EQ_LONG(run_case(BIND_BAD_MAGIC), 0);
  CHECK_EQ_LONG(run_case(BIND_BAD_VERSION), 0);
  CHECK_EQ_LONG(run_case(BIND_NULL_MASK), 0);
  CHECK_EQ_LONG(run_case(BIND_BAD_SELF), 0);
  TEST_DONE();
#endif
}
