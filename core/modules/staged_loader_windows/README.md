# staged_loader_windows

A **local (C2-side) module** that turns a Donut sRDI shellcode blob (e.g. the
`agent.exe.bin` produced by `agent generate --type exe`) into a
**self-unpacking Windows loader** that runs the shellcode inside a sacrificial
process. `--format` selects the host container: a **service exe** (default), a
plain **exe**, or a **DLL** exporting `Run()`/`SelfTest()`.

The shipped artifact is a **stager**: it carries the real loader as an
RC4-encrypted DLL and the shellcode as an RC4-encrypted blob, both embedded in
a data section. At run time the stager decrypts the DLL, maps it
**reflectively** (no `LoadLibrary`, no file on disk) and calls its exported
`StageMain`, which is what actually performs the injection. Neither the
loader's code nor the shellcode ever appears as a PE image on disk.

* The shellcode is **RC4-encrypted** with a fresh random key and passed to the
  stage as encrypted bytes; the stage decrypts it on demand. The stage DLL is
  itself **RC4-encrypted** with a separate fresh random key.
* The stage spawns the sacrificial process (default `svchost.exe`, also
  `dllhost.exe` or anything else) **suspended** and **early-bird injects** the
  decrypted blob: it is written to a fresh RW region, flipped to RX, and
  queued as a user APC on the suspended primary thread, so it runs before any
  of the sacrificial process's own code.
* A small trampoline parks the primary thread (`Sleep(INFINITE)`) after the
  blob returns, so the sacrificial process never reaches its own (often
  short-lived) `main` and does not `ExitProcess` the agent thread away.
* All injection-critical operations go through **indirect direct syscalls,
  and on x64 through the SilentMoonwalk desync spoofer** (unless built with
  `--smw off`), so a stack walk sees a `kernel32!BaseThreadInitThunk` frame
  instead of the loader's.
* The service is **one-shot**: it injects, verifies the child survived for the
  configured verify window (default ~5 s), reports `SERVICE_STOPPED` and
  exits, leaving the sacrificial process (with the agent inside) running.
  Delete the service afterwards.

Why early-bird + APC instead of module stomping? A full emp3r0r agent is
~16 MB expanded / ~6 MB as Donut shellcode; no single image-backed section in
a fresh `svchost.exe`/`dllhost.exe` (or `ntdll`) can hold that, so
module-stomping a spawned sacrificial is not feasible for the real payload.

## Usage

On the C2 console:

```
staged_loader --shellcode /path/to/agent.exe.bin [--format service|exe|dll]
           [--output out] [--process svchost.exe] [--process-args ""]
           [--arch x64] [--key <hex>] [--smw on|off] [--verify-ms 5000]
```

* `--shellcode` — the Donut sRDI blob (`*.bin`) to embed (required).
* `--output` — where to write the artifact (default
  `<shellcode dir>/<name>_svc.exe` for `service`, `<name>.exe` for `exe`,
  `<name>.dll` for `dll`).
* `--format` — host container:
  * `service` (default) — one-shot Windows service executable with the
    `--install`/`--start`/... commands.
  * `exe` — plain console executable with the service code compiled out;
    running it with no command performs one foreground injection.
  * `dll` — DLL exporting `Run()` (one injection) and `SelfTest()` (returns 0).
    The packed data lives in a data section, so it works both when loaded
    normally and when mapped in memory.
* `--process` — sacrificial process: a bare name is resolved under `System32`
  (`svchost.exe`, `dllhost.exe`, ...); anything containing a path separator is
  used verbatim.
* `--arch` — `x64` (default) or `x86`; must match the Donut blob. SMW is
  x64-only.
* `--key` — RC4 key for the shellcode blob as hex (1..256 bytes). Leave empty
  for a fresh random key per build (recommended). The stage DLL always gets a
  separate fresh random key.
* `--inject` — load method baked into the loader:
  * `apc` (default) — early-bird: QueueUserAPC on the suspended primary
    thread; the trampoline parks it afterwards, so even sacrificials that
    would exit on their own (svchost.exe, dllhost.exe) keep running the
    agent.
  * `ct` — classic CreateRemoteThread (Cobalt Strike style): the payload runs
    as a remote thread and the primary thread is resumed normally, so the
    sacrificial also runs its own code — pick one that stays alive
    (e.g. `notepad.exe`) or the process may exit right after the payload
    starts.

  Both modes enter the payload with the standard x64 stack alignment
  (`RSP % 16 == 8`); the early-bird trampoline reserves 8 bytes for this.
  Payloads whose entry prologue uses aligned SSE spills (e.g. Crystal Palace
  PICOs) depend on it.
* `--smw` — `on` (default) or `off`. `off` compiles SilentMoonwalk out of the
  stage: every indirect syscall then uses the plain `syscall; ret` gadget.
  Useful if the spoofer is flagged, or to drop the nasm build dependency.
  x64 only; x86 builds never use SMW.
* `--verify-ms` — how long (milliseconds) the loader watches the spawned
  process after injection before declaring success (default `5000`; `0`
  disables the check). Raise it for slow-starting payloads.
* `--debug` — keep verbose diagnostics in the binaries. **Off by default**: in
  production builds all logging is compiled out (`LOG()` expands to nothing,
  the long-form help is replaced by a terse command list), so the shipped
  `.exe` carries no descriptive strings. Use `--debug` only for lab builds.
  The `--selftest` output (a short `SELFTEST ...` line) is always available
  and is what CI validates.

### Build dependencies

The module is built on the C2 host, so it needs:

* a MinGW-w64 cross compiler matching `--arch`:
  * Linux: `apt install gcc-mingw-w64-x86-64` (or `gcc-mingw-w64-i686`)
  * Windows/msys2: `pacman -S mingw-w64-x86_64-gcc` (or `mingw-w64-i686-gcc`)
* a native C compiler (`cc`/`gcc`/`clang`) for the small RC4 pack helper.
* `nasm` when `--smw on` (the default) on x64 — it assembles the SilentMoonwalk
  desync stub. `--smw off` and x86 builds do not need it.

The shared RC4, indirect-syscall and SMW sources live in `core/modules/common/`
(mirrored to the operator workspace as `modules/common/` next to this module,
like `bof_common`); build.sh copies them from `../common/`.

### On the target

A `service` build is a one-shot service:

```
loader_svc.exe --install     # register service (LocalSystem, demand start)
sc start loader_svc          # one-shot: injects and stops itself
sc query loader_svc          # should report STOPPED with exit code 0
sc delete loader_svc         # clean up
```

An `exe` build is a plain launcher: running it with no command performs one
foreground injection.

```
loader.exe                   # inject once
loader.exe --selftest        # unstage + decrypt, print SELFTEST
```

A `dll` build exports two functions for any loader (for example
`rundll32 loader.dll,Run`):

```c
int __cdecl Run(void);       /* one foreground injection */
int __cdecl SelfTest(void);  /* 0 on success */
```

A `service` build also accepts these console commands:

| command             | effect                                          |
| ------------------- | ----------------------------------------------- |
| `--install`         | register the service under the exe basename     |
| `--uninstall`       | remove the service                              |
| `--start` / `--stop`| start / stop it                                 |
| `--run`             | inject once in the foreground (debugging)       |
| `--selftest`        | unstage the loader, decrypt the blob and print a parseable `SELFTEST ...` line (sizes, head/tail hex, SSN and SMW status) — never spawns a process |

`--selftest` is what CI uses to verify the staging and RC4 pipeline
end to end without injecting anything. It exercises the real reflective
loader, the Zw-twin SSN ranking and (x64) a live SilentMoonwalk-spoofed
`NtAllocateVirtualMemory`/`NtWriteVirtualMemory`/`NtProtectVirtualMemory`
round trip.

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

At runtime the process:

1. reads the four embedded blobs (stage DLL, stage key, shellcode, shellcode
   key) and RC4-decrypts the stage DLL;
2. reflectively maps the stage DLL (`reflect.c`): copies sections, applies
   base relocations against the actual base, resolves the import table with
   the real `LoadLibraryA`/`GetProcAddress`, sets per-section protections,
   initializes static TLS and runs `DllMain(DLL_PROCESS_ATTACH)`;
3. resolves the `StageMain` export and calls it with the wide command line and
   the still-encrypted blob/key;
4. `StageMain` decrypts the blob, spawns the sacrificial process with
   `CREATE_SUSPENDED`;
5. allocates an RW region in the child, writes a tiny trampoline
   (`call blob; Sleep(INFINITE)`) then the blob, flips it to RX;
6. `NtQueueApcThread` on the suspended primary thread and `ResumeThread` — the
   APC fires before the sacrificial process's own code, running the blob;
7. watches the child for the configured `--verify-ms` window (bails out if it
   died right after resume) and reports `SERVICE_STOPPED`, leaving the agent
   running inside `svchost.exe`.

Notes / trade-offs:

* RC4 here is obfuscation of the stage and blob at rest, not a secret-key
  primitive — the keys ship in the same binary. Rotate the blob key per build
  via the random default; the stage key is always random.
* The trampoline parks the primary thread with `kernel32!Sleep` resolved in
  the loader's own process; system DLLs share one per-boot base across
  processes, so the absolute address is valid in the freshly spawned child.
* The injected region is allocated RW, written, then flipped to
  PAGE_EXECUTE_READ - there is no RWX window. Donut blobs resolve their own
  APIs and decode into a freshly allocated buffer, so read+execute is
  sufficient.
* The loader service runs as `LocalSystem` by default — the agent then beacons
  as SYSTEM inside the sacrificial process.
* If the shellcode crashes the child during the early-bird run, the loader
  reports failure instead of pretending the injection worked.

### Direct syscalls

On x64 all injection-critical operations (NtAllocateVirtualMemory,
NtWriteVirtualMemory, NtProtectVirtualMemory, NtQueueApcThread,
NtCreateThreadEx) are issued as **indirect direct syscalls**, ported from
`core/lib/syscall`: the PEB is walked to find ntdll, SSNs are derived by
ranking `Zw*` exports by address, and the `syscall` instruction is executed
through a `syscall; ret` gadget inside ntdll. This bypasses kernel32/
kernelbase wrappers entirely - notably `QueueUserAPC`, whose kernelbase
implementation routes through `NtQueueApcThreadEx2` and is unreliable on some
hardened hosts. x86 builds fall back to the Win32 APIs.

### Stack spoofing (SMW)

The SilentMoonwalk desync spoofer (`../common/smw`, copied from
`core/lib/syscall/smw/csrc`) wraps every direct syscall that takes at most 8
arguments (`ntsys.c`). It synthesizes fake unwind frames terminating in
`kernel32!BaseThreadInitThunk`/`ntdll!RtlUserThreadStart`, so an EDR stack
walk no longer sees the payload's return address. The spoofer is plain C +
NASM and does not have the cgo stack/unwind conflict that forced
`lib/syscall` to disable SMW in the Go agent.

The spoofer is initialized once per process (`smw_ensure_init`) and the
`syscall; ret` gadget is reached through its desync trampoline with the SSN in
EAX and the first argument in R10. `NtCreateThreadEx` has 11 arguments, above
the stub's 8-argument ceiling, and therefore keeps the plain indirect path
(only used by `--inject ct`). If SMW cannot initialize on a host, all calls
transparently fall back to the plain gadget.
