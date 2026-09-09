# svc_loader

A **local (C2-side) module** that turns a Donut sRDI shellcode blob (e.g. the
`agent.exe.bin` produced by `agent generate --type exe`) into a **one-shot
Windows service executable** that runs the shellcode inside a sacrificial
process.

* The shellcode is **RC4-encrypted** with a fresh random key and embedded as
  an **RCDATA resource** of the `.exe` (`IDR_PAYLOAD = 101`, `IDR_KEY = 102`)
  — the blob never appears in plaintext on disk.
* On service start the loader spawns the sacrificial process (default
  `svchost.exe`, also `dllhost.exe` or anything else) **suspended** and
  **early-bird injects** the decrypted blob: it is written to a fresh RWX
  region and queued as a user APC on the suspended primary thread, so it runs
  before any of the sacrificial process's own code.
* A small trampoline parks the primary thread (`Sleep(INFINITE)`) after the
  blob returns, so the sacrificial process never reaches its own (often
  short-lived) `main` and does not `ExitProcess` the agent thread away.
  Donut blobs generated with RunThread keep the agent alive in its own thread
  inside the sacrificial container.
* The service is **one-shot**: it injects, verifies the child survived for
  ~5 seconds, reports `SERVICE_STOPPED` and exits, leaving the sacrificial
  process (with the agent inside) running. Delete the service afterwards.

Why early-bird + APC instead of module stomping? A full emp3r0r agent is
~16 MB expanded / ~6 MB as Donut shellcode; no single image-backed section in
a fresh `svchost.exe`/`dllhost.exe` (or `ntdll`) can hold that, so
module-stomping a spawned sacrificial is not feasible for the real payload.

## Usage

On the C2 console:

```
svc_loader --shellcode /path/to/agent.exe.bin [--output out.exe]
           [--process svchost.exe] [--process-args ""] [--arch x64] [--key <hex>]
```

* `--shellcode` — the Donut sRDI blob (`*.bin`) to embed (required).
* `--output` — where to write the loader `.exe` (default
  `<shellcode dir>/<name>_svc.exe`).
* `--process` — sacrificial process: a bare name is resolved under `System32`
  (`svchost.exe`, `dllhost.exe`, ...); anything containing a path separator is
  used verbatim.
* `--arch` — `x64` (default) or `x86`; must match the Donut blob.
* `--key` — RC4 key as hex (1..256 bytes). Leave empty for a fresh random key
  per build (recommended).
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
* `--debug` — keep verbose diagnostics in the binary. **Off by default**: in
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

The shared RC4 sources live in `core/modules/common/` (mirrored to the
operator workspace as `modules/common/` next to this module, like
`bof_common`); build.sh copies them from `../common/` into its scratch dir.

### On the target

```
loader_svc.exe --install     # register service (LocalSystem, demand start)
sc start loader_svc          # one-shot: injects and stops itself
sc query loader_svc          # should report STOPPED with exit code 0
sc delete loader_svc         # clean up
```

The generated `.exe` is also a small CLI:

| command             | effect                                          |
| ------------------- | ----------------------------------------------- |
| `--install`         | register the service under the exe basename     |
| `--uninstall`       | remove the service                              |
| `--start` / `--stop`| start / stop it                                 |
| `--run`             | inject once in the foreground (debugging)       |
| `--selftest`        | decrypt the embedded payload and print a parseable `SELFTEST ...` line (sizes + head/tail hex) — never spawns a process |

`--selftest` is what CI uses to verify the resource/RC4 pipeline end to end
without injecting anything.

## How it works

```
pack (host)                 loader.rc (windres)          loader.exe
agent.bin ──RC4(key)──▶ payload.bin ──▶ RCDATA 101 ──▶ resources.o ──┐
                key ─────────────▶ key.bin ────▶ RCDATA 102 ──────────┴──▶ loader.exe
                                                          loader.c (service + early-bird inject)
```

At runtime the service:

1. `FindResourceW`/`LoadResource` both RCDATA resources and RC4-decrypts the
   blob in memory;
2. spawns the sacrificial process with `CREATE_SUSPENDED`;
3. `VirtualAllocEx(PAGE_EXECUTE_READWRITE)` in the child, writes a tiny
   trampoline (`call blob; Sleep(INFINITE)`) then the blob;
4. `QueueUserAPC` on the suspended primary thread and `ResumeThread` — the
   APC fires before the sacrificial process's own code, running the blob;
5. watches the child for ~5 s (bails out if it died right after resume) and
   reports `SERVICE_STOPPED`, leaving the agent running inside `svchost.exe`.

Notes / trade-offs:

* RC4 here is obfuscation of the blob at rest, not a secret-key primitive —
  the key ships in the same binary (`IDR_KEY`). Rotate the key per build via
  the random default.
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

### Stack spoofing (SMW, planned)

`core/lib/syscall/smw/csrc` (SilentMoonwalk desync spoofer, C + NASM) can be
vendored into this module to spoof the call stack around each syscall: the
direct-syscall `call *gadget` in `nt_invoke` would be replaced by
`silentmoonwalk_spoof_call`, synthesizing fake unwind frames terminating in
`BaseThreadInitThunk`/`RtlUserThreadStart`. The loader is plain C - the cgo
stack/unwind conflict that forced lib/syscall to disable SMW in the agent
does not apply here. Build requirements: nasm at build time (already present
on CI Windows runners). Not yet wired in.
