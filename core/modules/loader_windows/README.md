# loader_windows

A C2-side module that turns a Donut sRDI shellcode blob (for example the
`agent.exe.bin` produced by `agent generate --type exe`) into a self-unpacking
Windows loader. The loader runs the shellcode inside a sacrificial process.
`--format` selects the host container: a service executable (default), a plain
executable, or a DLL exporting `Run()`.

The artifact is a thin stager. It carries the real loader as an RC4-encrypted
DLL and the shellcode as a separate RC4-encrypted blob, both in a data section.
At run time the stager decrypts the DLL, maps it reflectively — no
`LoadLibrary`, no file on disk — and calls its exported `StageMain`, which
performs the injection. Neither the loader's code nor the shellcode ever
appears as a PE image on disk.

The stage spawns the sacrificial process (default `svchost.exe`, also
`dllhost.exe`, or anything else) suspended and early-bird injects the decrypted
blob: the blob is written to a fresh RW region, flipped to RX, and queued as a
user APC on the suspended primary thread, so it runs before the sacrificial
process's own code. A small trampoline then parks that thread with
`Sleep(INFINITE)`, so the host process never reaches its own `main` and never
calls `ExitProcess` on the agent. Injection-critical operations go through
indirect syscalls, and on x64 through the SilentMoonwalk desync spoofer unless
built with `--smw off`, so a stack walk sees a `kernel32!BaseThreadInitThunk`
frame instead of the loader's.

The service is one-shot: it injects, verifies the child survived for the
configured window (about 5 seconds by default), reports `SERVICE_STOPPED`, and
exits, leaving the sacrificial process and the agent inside it running. Delete
the service afterwards.

Early-bird APC injection is used instead of module stomping because a full
emp3r0r agent is roughly 16 MB expanded (~6 MB as Donut shellcode). No single
image-backed section in a fresh `svchost.exe`, `dllhost.exe`, or `ntdll` can
hold that, so stomping a spawned sacrificial is not feasible for the real
payload.

## Usage

From the C2 console:

```
loader_windows --shellcode /path/to/agent.exe.bin [--format service|exe|dll]
    [--output out] [--process svchost.exe] [--process-args ""]
    [--arch x64] [--key <hex>] [--smw on|off] [--verify-ms 5000]
    [--inject apc|ct] [--debug] [--debug-child]
```

### Options

- `--shellcode` — Donut sRDI blob (`.bin`) to embed. Required.
- `--format` — host container:
  - `service` (default): one-shot Windows service with
    `--install`/`--start`/`--stop`/`--run` commands.
  - `exe`: plain console executable; running it with no command performs one
    foreground injection.
  - `dll`: DLL exporting `Run()`, for normal or in-memory loading.
- `--output` — output path. Defaults to `<shellcode dir>/<name>_svc.exe`,
  `<name>.exe`, or `<name>.dll` depending on `--format`.
- `--process` — sacrificial process. A bare name is resolved under `System32`
  (`svchost.exe`, `dllhost.exe`, ...); a value containing a path separator is
  used verbatim.
- `--arch` — `x64` (default) or `x86`; must match the Donut blob. SilentMoonwalk
  is x64-only.
- `--key` — RC4 key for the shellcode blob as hex (1..256 bytes). Leave empty
  for a fresh random key per build. The stage DLL always gets its own random
  key.
- `--inject` — load method:
  - `apc` (default): early-bird `QueueUserAPC` on the suspended primary
    thread. The trampoline parks the thread afterwards, so even hosts that
    would exit on their own (`svchost.exe`, `dllhost.exe`) keep running the
    agent.
  - `ct`: classic `CreateRemoteThread`. The payload runs as a remote thread and
    the primary thread is resumed normally, so the host also runs its own code.
    Pick a process that stays alive (for example `notepad.exe`) or it may exit
    right after the payload starts.

  Both modes enter the payload with the standard x64 stack alignment
  (`RSP % 16 == 8`); the early-bird trampoline reserves the extra 8 bytes.
  Payloads whose entry prologue uses aligned SSE spills (such as Crystal
  Palace PICOs) depend on this.
- `--smw` — `on` (default) or `off`. `off` compiles SilentMoonwalk out of the
  stage and uses a plain `syscall; ret` gadget for every indirect syscall.
  Useful when the spoofer is flagged or to drop the nasm build dependency.
  Ignored on x86.
- `--verify-ms` — how long the loader watches the spawned process after
  injection before declaring success, in milliseconds (default `5000`; `0`
  disables the check). Raise it for slow-starting payloads.
- `--debug` — keep verbose diagnostics in the binaries. Off by default: in
  production builds all diagnostic output is compiled out (`LOG()` expands to
  nothing, help text and installer messages are not built), so the shipped
  binary carries no descriptive strings.
- `--debug-child` — lab builds only. Create the sacrificial process as a
  debuggee so the loader itself reports the child's first exception (code,
  fault address, access type, and whether the fault is inside the injected
  region) and its exit code. This is how to see why a short-lived child dies
  when it cannot be attached to in time. Implies `--debug`.

## On the target

A `service` build is a one-shot service:

```
loader_svc.exe --install     # register the service (LocalSystem, demand start)
sc start loader_svc          # injects once and stops itself
sc query loader_svc          # should report STOPPED, exit code 0
sc delete loader_svc         # clean up
```

An `exe` build is a plain launcher:

```
loader.exe                   # inject once in the foreground
```

A `dll` build exports one function for any loader (for example
`rundll32 loader.dll,Run`):

```c
int __cdecl Run(void);       /* one foreground injection */
```

A `service` build also accepts `--uninstall`, `--start`, `--stop`, and `--run`
(foreground injection for debugging).

## Build dependencies

The module is built on the C2 host and needs:

- [zig](https://ziglang.org/download) — the default cross compiler, invoked as
  `zig cc`. `core/build.py` installs the pinned release automatically. One
  pinned toolchain across hosts keeps the generated loader consistent, which
  matters because the reflective stage is sensitive to compiler and linker
  layout. `--cc` overrides it with any other cross compiler, for example a
  MinGW-w64 gcc:
  - Linux: `apt install gcc-mingw-w64-x86-64` (or `gcc-mingw-w64-i686`)
  - Windows/msys2: `pacman -S mingw-w64-x86_64-gcc` (or `mingw-w64-i686-gcc`)
- a native C compiler (`cc`/`gcc`/`clang`) for the small RC4 pack helper.
- `nasm` when `--smw on` (the default) on x64, to assemble the SilentMoonwalk
  desync stub. `--smw off` and x86 builds do not need it.

The shared RC4, indirect-syscall, and SilentMoonwalk sources live in
`core/modules/common/` and are mirrored to the operator workspace as
`modules/common/` next to this module, like `bof_common`.

## How it works

```
build (host)                              host (exe or dll)
                                              ┌──────────────────────────┐
loader.c ──mingw -shared──▶ stage.dll ─pack─┐ │ .rdata (stage_data.S)    │
shellcode.bin ────────────────pack──────────┼▶│  stage.bin  stage_key    │
                            (RC4 each)      ┘ │  payload.bin  key        │
                                              └──────────────────────────┘
                                                           │
                                                           ▼
                            bootstrap.c: decrypt stage.dll ─▶ reflect_load()
                                                           │  (map sections,
                                                           │   relocs, imports,
                                                           │   TLS, DllMain)
                                                           ▼
                            StageMain(argc, argv, payload, key)
                                                           │
                                                           ▼
                     decrypt blob ─▶ spawn svchost suspended ─▶ early-bird
                     APC (indirect syscalls + SMW) ─▶ trampoline parks
                     primary thread ─▶ SERVICE_STOPPED
```

At run time the process:

1. reads the four embedded blobs (stage DLL, stage key, shellcode, shellcode
   key) and RC4-decrypts the stage DLL;
2. reflectively maps the stage DLL (`reflect.c`): copies sections, applies
   base relocations against the actual base, resolves imports with the real
   `LoadLibraryA`/`GetProcAddress`, sets per-section protections, initializes
   static TLS, and runs `DllMain(DLL_PROCESS_ATTACH)`;
3. resolves the `StageMain` export and calls it with the wide command line and
   the still-encrypted blob and key;
4. `StageMain` decrypts the blob and spawns the sacrificial process with
   `CREATE_SUSPENDED`;
5. allocates an RW region in the child, writes a tiny trampoline
   (`call blob; Sleep(INFINITE)`) and then the blob, and flips the region to
   RX;
6. calls `NtQueueApcThread` on the suspended primary thread and resumes it, so
   the APC fires before the host's own code;
7. watches the child for the `--verify-ms` window, bailing out if it died right
   after resume, then reports `SERVICE_STOPPED`.

Trade-offs:

- RC4 here obfuscates the stage and blob at rest; it is not a secret-key
  primitive, since the keys ship in the same binary. Rotate the blob key per
  build with the random default; the stage key is always random.
- The trampoline parks the primary thread with `kernel32!Sleep` resolved in the
  loader's own process. System DLLs share one per-boot base across processes,
  so that absolute address is valid in the freshly spawned child.
- The injected region is never RWX: it is allocated RW, written, then flipped
  to `PAGE_EXECUTE_READ`. Donut blobs resolve their own APIs and decode into a
  fresh buffer, so read+execute is enough.
- The loader service runs as `LocalSystem` by default, so the agent beacons as
  SYSTEM inside the sacrificial process.
- If the shellcode crashes the child during the early-bird run, the loader
  reports failure instead of pretending the injection worked.

## Direct syscalls

On x64, all injection-critical operations (`NtAllocateVirtualMemory`,
`NtWriteVirtualMemory`, `NtProtectVirtualMemory`, `NtQueueApcThread`,
`NtCreateThreadEx`) are issued as indirect direct syscalls ported from
`core/lib/syscall`. The PEB is walked to find ntdll, SSNs are derived by
ranking `Zw*` exports by address, and the `syscall` instruction is executed
through a `syscall; ret` gadget inside ntdll. This bypasses the kernel32 and
kernelbase wrappers entirely — notably `QueueUserAPC`, whose kernelbase
implementation routes through `NtQueueApcThreadEx2` and is unreliable on some
hardened hosts. x86 builds fall back to the Win32 APIs.

## Stack spoofing (SilentMoonwalk)

The SilentMoonwalk desync spoofer in `../common/smw` (copied from
`core/lib/syscall/smw/csrc`) wraps every direct syscall that takes at most
eight arguments. It synthesizes fake unwind frames terminating in
`kernel32!BaseThreadInitThunk` and `ntdll!RtlUserThreadStart`, so an EDR stack
walk no longer sees the payload's return address. The spoofer is plain C and
NASM and avoids the cgo stack and unwind conflict that forced `lib/syscall` to
disable SilentMoonwalk in the Go agent.

The spoofer initializes once per process (`smw_ensure_init`), and the
`syscall; ret` gadget is reached through its desync trampoline with the SSN in
EAX and the first argument in R10. `NtCreateThreadEx` has eleven arguments,
above the stub's eight-argument ceiling, so it keeps the plain indirect path
(only used by `--inject ct`). If SilentMoonwalk cannot initialize on a host,
all calls fall back transparently to the plain gadget.
