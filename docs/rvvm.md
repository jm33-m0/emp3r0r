# RISC-V BOF modules

`rv` modules run a **BOF object** inside a tiny RV32IMA interpreter on the
agent. The payload is architecture-independent: the same RV32 executable runs
on every supported Linux agent architecture, because only the interpreter is
host code.

`rv` is BOF-only. A module build produces an RV32 static executable containing:

- musl,
- a guest entry shim that receives the packed arguments in a reserved section,
- the BOF entry point `int go(char *args, int len)`.

The interpreter loads the executable, builds the initial Linux stack, `auxv`
and environment, starts at musl's `_start`, and lets musl initialize TLS,
errno, stdio, the allocator, and libc. The environment mirrors the agent's
environment, like a native BOF sees through `getEnviron()`. `main` then calls
`go`. The only host boundary is the Linux syscall gate.

## Prerequisites

- The `rvvm_linux` dependency module. The C2 hosts it automatically for
  `--riscv` runs. `rv` modules run on Linux agents only.
- The agent must be able to map the interpreter: `memmod` on the Go agent
  (386/amd64/arm/arm64 on Linux) and `elfload` on the C agent
  (x86_64/aarch64/riscv64).
- The `zig` toolchain shipped with emp3r0r. It compiles the BOF for
  `riscv32-linux-musl` and links the static guest executable.

## Running a BOF in the interpreter

Every `coff` module gets a `--riscv` option. With it, the C2 recompiles the
module's BOF sources for RV32, links each payload with musl, and dispatches the
result to the interpreter:

```text
sa_linux_pwd --riscv
whoami --riscv
```

The `--riscv` flag selects the RISC-V build for that invocation; without it the
same module still builds and runs as a native BOF. With the flag, the C2 puts
the module toolchain in RV32 mode before running the build:

- `CC`/`CXX` shims target `riscv32-linux-musl`
- `ZIG_TARGET=riscv32-linux-musl`
- `RV_TARGET=riscv32-linux-musl`
- `EMP3R0R_BOF_ARCH=riscv32`
- `EMP3R0R_TARGET=riscv32`

The C2 runs the module's `rv_build.sh` if present, otherwise its normal build
(`build`/`make_all.sh`). The build emits an RV32 object next to the native one:

```text
pwd.o             -> pwd.rv.o  -> pwd.rv
whoami.x64.o      -> whoami.rv.o -> whoami.rv
```

The C2 links `*.rv.o` with `core/internal/cc/modules/rvguest/main.c` and
`guest.ld` into a static `ET_EXEC` image. Modules do not need to invoke the
linker themselves.

A module that wants to compile RV32 objects directly can use:

```sh
zig cc -target riscv32-linux-musl -mcpu=generic_rv32 -O2 -g0 -fno-pic \
  -mno-relax -msmall-data-limit=0 -fno-asynchronous-unwind-tables \
  -fno-unwind-tables -fno-builtin -fno-stack-protector -fno-sanitize=all \
  -I includes -c -o pwd.rv.o pwd.c
```

### Libraries

A module can add RISC-V static libraries or object files to
`riscv_libraries`. They are linked into each guest executable at build time:

```json
{
  "name": "my_bof",
  "platform": "Linux",
  "riscv_libraries": ["libkit.a"],
  "agent_config": { "files": ["my_bof.o"], "type": "coff" },
  "invocation": { "coff_export": "go" }
}
```

Build the library for `riscv32-linux-musl` with `zig` and the same CPU flags.
This is how a BOF gains new capabilities without adding a host proxy: link
zlib, libbpf, OpenSSL, or another library into the guest executable.

`riscv_libraries` are linked on the C2; nothing is delivered to the agent at
run time.

## Syscall gate

Guest `ecall` instructions enter one Linux syscall gate. The gate implements
the RV32 Linux ABI for the calls used by musl and common BOFs:

- process and identity: `exit`, `exit_group`, `getpid`, `getppid`, `getuid`,
  `geteuid`, `getgid`, `getegid`, `getgroups`, `uname`, `sched_getaffinity`
- files and directories: `openat`, `close`, `read`, `readv`, `write`,
  `writev`, `lseek`, `getdents64`, `readlinkat`, `fchmodat`, `statx`
- memory and runtime: `brk`, `mmap`, `munmap`, `mprotect`, `set_tid_address`,
  `set_robust_list`, `rseq`, `prlimit64`, `getrandom`, `clock_gettime64`
- network: `socket`, `bind`, `sendto`, `recvfrom`, `setsockopt`, `recvmsg`
- startup: `getcwd`, `fcntl`

Unsupported calls return `-ENOSYS`. Adding a capability normally means adding
a library or a syscall case, not a BOF-specific proxy.

## Constraints

- RV32IMA only; no compressed instructions, no floating point, no MMU.
- Single thread, no guest `fork` or `clone`.
- 64 MiB guest address space, laid out like a normal process (image, brk heap,
  51 MiB mmap arena, stack, argument block). The guest executable, its libc, TLS,
  heap, stack, and program headers all live in it.
- A run is bounded to a loose instruction budget and 8 MiB of output. The
  budget is a runaway-guest guard, not a latency bound: scanning BOFs such as
  `tasklist` legitimately run for hundreds of millions of guest instructions.
  An illegal instruction, a misaligned jump, an out-of-range load/store, a bad
  ELF image or a budget overrun reports an error; it never crashes the agent.
- The interpreter is mapped only for the run and unmapped immediately
  afterwards. `RVVM=0` compiles the C agent support out.
