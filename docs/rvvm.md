# RISC-V BOF modules

`rv` modules run a **BOF object** inside a tiny RV32IMA interpreter on the
agent. The payload is architecture-independent: the same RV32 relocatable
object runs on every Linux and Windows agent, because only the interpreter is
host code.

`rv` is BOF-only. The payload is an `ET_REL` RISC-V object with the standard
BOF entry point `int go(char *args, int len)`. The interpreter maps it,
resolves its imports against the embedded guest runtime (Beacon API and a libc
subset), and calls the export with the packed COFF argument buffer.

## Prerequisites

- The `rvvm_linux` (Linux) or `rvvm_windows` (Windows) dependency module. The
  C2 selects and hosts it automatically from the `rv` module's `platform`.
- The agent must be able to map the interpreter: `memmod` on the Go agent
  (386/amd64/arm/arm64 on Windows, 386/amd64/arm64 on Linux) and `elfload` on
  the C agent (x86_64/aarch64/riscv64). The Linux interpreter links libc (like
  `coffloader_linux`); the Windows interpreter imports only `kernel32`.
- To build a payload: the `zig` toolchain shipped with emp3r0r (the C2
  provides `ZIG` to module builds).

## Running a BOF in the interpreter

Every `coff` module gets a `--riscv` option. With it, the C2 recompiles the
module's BOF sources for RV32 and dispatches the result to the interpreter; the
manifest stays a normal COFF module:

```text
sa_linux_pwd --riscv
whoami --riscv
```

The C2 runs the module's `rv_build.sh` if present, otherwise its normal build
(`build`/`make_all.sh`) with `EMP3R0R_BOF_ARCH=riscv32`. The build must emit
the RV32 object next to the native one: `pwd.o` -> `pwd.rv.o`,
`whoami.x64.o` -> `whoami.rv.o`. Modules without a source build report that no
RISC-V object was produced.

Build an RV32 `ET_REL` object with:

```sh
zig cc -target riscv32-linux-musl -mcpu=generic_rv32 -O2 -g0 -fno-pic \
  -mno-relax -msmall-data-limit=0 -fno-asynchronous-unwind-tables \
  -fno-unwind-tables -fno-builtin -fno-stack-protector -fno-sanitize=all \
  -I includes -c -o pwd.rv.o pwd.c
```

- `-mcpu=generic_rv32`: the interpreter implements RV32IMA without the
  compressed-instruction extension.
- `-fno-pic`, `-mno-relax`, `-g0` and no unwind tables keep the object to the
  relocation types the loader implements.
- Do not strip: the loader needs `.symtab` for the export and imports.

### Libraries

A module can ship RISC-V libraries alongside the BOF and list them in
`riscv_libraries`. They are hosted with the multi-file module mechanism, sent
to the agent, kept in encrypted memfs, and copied into guest RAM by the
interpreter:

```json
{
  "name": "my_bof",
  "platform": "Linux",
  "riscv_libraries": ["libkit.rv.o"],
  "agent_config": { "files": ["my_bof.o"], "type": "coff" },
  "invocation": { "coff_export": "go" }
}
```

Libraries are ordinary RV32 `ET_REL` objects. The loader places the BOF, the
interpreter runtime and up to three libraries in guest RAM, builds one symbol
table, resolves cross-object imports, and relocates everything as a single
image. Undefined symbols that are not in the runtime or a delivered library are
rejected with a named `unresolved symbol`.

Windows BOF sources use the `MODULE$Function` import convention
(`KERNEL32$VirtualAlloc`, `MSVCRT$memcpy`, ...). The loader strips the module
prefix and resolves the function name against the guest runtime, exactly as the
Windows COFF loader resolves it against the host DLL. The embedded runtime
implements a core subset (memory, handles, strings, time, and the POSIX-layer
services below); other imports fail at load time with a named symbol.

## Host calls

The guest runtime uses a mailbox at `0x801ff000` for `open`/`read`/`write`/
`close`/`lseek`/`getcwd`/`stat`/`readdir`/`uname`/`getuid`/`getenv`/
`readlink`/`chmod`/`usleep`/`getpwuid`/`getgrgid` services and MMIO
`0x10001000` for exit. The Linux backend serves them with libc; the Windows
backend uses `kernel32`.

## Constraints

- RV32IMA only; no compressed instructions, no floating point, no MMU.
- Single thread, no guest syscalls.
- 8 MiB guest RAM: up to 512 KiB of BOF sections, a ~1.1 MiB runtime (with a
  1 MiB heap), a host-call mailbox, and a 128 KiB stack.
- A run is bounded to 512M instructions and 1 MiB of output. An illegal
  instruction, a misaligned jump, an out-of-range load/store, an unresolved
  symbol or a budget overrun reports an error; it never crashes the agent.
- The interpreter is mapped only for the run and unmapped immediately
  afterwards. `RVVM=0` compiles the C agent support out.
