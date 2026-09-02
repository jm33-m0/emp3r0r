# emp3r0r Module Development Guide

This guide details the end-to-end process of creating, configuring, and building new modules for emp3r0r. Currently, emp3r0r officially supports **BOF (COFF)** and **Starlark** modules.

---

## 1. Directory Structure

All custom modules reside inside the `core/modules/` directory. You can organize your modules in two ways:

1. **Standalone Module:** A single folder for a specific module (e.g., `core/modules/process_list_handles/`).
2. **Module Suite:** A folder containing a collection of related modules defined in a single configuration (e.g., `core/modules/Remote-OPs/` or `core/modules/SA/`).

A standard module suite repository looks like this:

```text
core/modules/MyModuleSuite/
├── config.json         # Mandatory: The JSON registry defining the modules
├── make_all.sh         # Optional: Executed automatically by build.sh
├── src/                # Your C/C++ or Starlark source code
│   └── MyBof/
│       ├── bof.c
│       └── Makefile
```

---

## 2. The `config.json` Format

The `config.json` file is the heart of your module. It is a JSON array containing one or more module definitions. The C2 parses this file (via `readModConfigs` in `modcustom.go`) to dynamically register the commands, their help menus, and their execution payloads.

### Example Configuration (BOF)

See `core/modules/hello_linux/config.json` for a real-world example:

```json
[
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
]
```

### Example Configuration (Starlark)

See `core/modules/starlark_procinfo/config.json` for a real-world example:

```json
[
  {
    "name": "starlark_procinfo",
    "build": "",
    "author": "you",
    "date": "2026-06-22",
    "comment": "List running process info on Linux using Starlark script engine",
    "is_local": false,
    "platform": "Linux",
    "path": "",
    "fileless": true,
    "parameters": [
      {
        "name": "filter",
        "description": "Optional search filter for process name or cmdline",
        "default": "",
        "type": "string",
        "required": false
      }
    ],
    "agent_config": {
      "exec": "run.star",
      "files": ["run.star"],
      "in_memory": true,
      "type": "starlark",
      "interactive": false
    },
    "invocation": {}
  }
]
```

### Minimal Source Code Examples

#### BOF Source (`core/modules/hello_linux/hello_linux.c`)

```c
#include "beacon_helpers.h"
#include "syscall_helpers.h"

// Declare BeaconPrintf
extern void BeaconPrintf(int type, const char *fmt, ...);

void go(char *args, int len) {
  datap parser;
  BeaconDataParse(&parser, args, len);

  char *who = BeaconDataString(&parser);
  if (!who || !who[0]) {
    who = "World";
  }

  BeaconPrintf(0, "Hello %s!", who);
}
```

#### Starlark Source (`core/modules/starlark_procinfo/run.star`)

```python
CAPABILITIES = [
    "CAP_CHOWN", "CAP_DAC_OVERRIDE", "CAP_DAC_READ_SEARCH", "CAP_FOWNER",
    "CAP_FSETID", "CAP_KILL", "CAP_SETGID", "CAP_SETUID", "CAP_SETPCAP",
    "CAP_LINUX_IMMUTABLE", "CAP_NET_BIND_SERVICE", "CAP_NET_BROADCAST",
    "CAP_NET_ADMIN", "CAP_NET_RAW", "CAP_IPC_LOCK", "CAP_IPC_OWNER",
    "CAP_SYS_MODULE", "CAP_SYS_RAWIO", "CAP_SYS_CHROOT", "CAP_SYS_PTRACE",
    "CAP_SYS_PACCT", "CAP_SYS_ADMIN", "CAP_SYS_BOOT", "CAP_SYS_NICE",
    "CAP_SYS_RESOURCE", "CAP_SYS_TIME", "CAP_SYS_TTY_CONFIG", "CAP_MKNOD",
    "CAP_LEASE", "CAP_AUDIT_WRITE", "CAP_AUDIT_CONTROL", "CAP_SETFCAP",
    "CAP_MAC_OVERRIDE", "CAP_MAC_ADMIN", "CAP_SYSLOG", "CAP_WAKE_ALARM",
    "CAP_BLOCK_SUSPEND", "CAP_AUDIT_READ", "CAP_PERFMON", "CAP_BPF",
    "CAP_CHECKPOINT_RESTORE"
]

def decode_caps(hex_str):
    if not hex_str or hex_str == "N/A":
        return "N/A"
    val = int(hex_str, 16)
    if val == 0:
        return "None"
    caps = []
    for i in range(len(CAPABILITIES)):
        if (val & (1 << i)) != 0:
            caps.append(CAPABILITIES[i])
    if not caps:
        return hex_str
    return ", ".join(caps)

def parse_status(status_text):
    info = {}
    for line in status_text.split('\n'):
        if not line:
            continue
        parts = line.split(':\t')
        if len(parts) == 2:
            key = parts[0].strip()
            val = parts[1].strip()
            info[key] = val
    return info

def format_ns(ns_ls_output):
    ns_dict = {}
    for line in ns_ls_output.split('\n'):
        if " -> " in line:
            parts = line.split(" -> ")
            if len(parts) == 2:
                name = parts[0].split(" ")[-1]
                target = parts[1].strip()
                ns_dict[name] = target
    return ns_dict

def main(*args):
    print("==================================================")
    print(" Current Process Info ")
    print("==================================================")

    cmdline = read_file("/proc/self/cmdline").strip("\x00").replace("\x00", " ")
    print("Cmdline:    %s" % (cmdline or "N/A"))

    status_text = read_file("/proc/self/status")
    status = parse_status(status_text)

    print("\n--- Identity & Privileges ---")
    print("Name:       %s" % status.get("Name", "N/A"))
    print("State:      %s" % status.get("State", "N/A"))
    print("PID:        %s" % status.get("Pid", "N/A"))
    print("PPID:       %s" % status.get("PPid", "N/A"))
    print("UIDs:       %s (Real, Effective, Saved, FS)" % status.get("Uid", "N/A"))
    print("GIDs:       %s (Real, Effective, Saved, FS)" % status.get("Gid", "N/A"))
    print("Groups:     %s" % status.get("Groups", "N/A"))

    print("\n--- Capabilities ---")
    print("Inheritable:\n  %s" % decode_caps(status.get("CapInh", "N/A")))
    print("Permitted:\n  %s" % decode_caps(status.get("CapPrm", "N/A")))
    print("Effective:\n  %s" % decode_caps(status.get("CapEff", "N/A")))
    print("Bounding:\n  %s" % decode_caps(status.get("CapBnd", "N/A")))
    print("Ambient:\n  %s" % decode_caps(status.get("CapAmb", "N/A")))
    print("NoNewPrivs: %s" % status.get("NoNewPrivs", "N/A"))

    print("\n--- Cgroups ---")
    cgroup_text = read_file("/proc/self/cgroup")
    for line in cgroup_text.split('\n'):
        if line:
            parts = line.split(':')
            if len(parts) >= 3:
                print(parts[2])

    print("\n--- Namespaces ---")
    ns_info = exec_cmd("ls", ["-l", "/proc/self/ns"])
    namespaces = format_ns(ns_info)
    for k in sorted(namespaces.keys()):
        k_padded = k + ":"
        if len(k_padded) < 12:
            k_padded = k_padded + " " * (12 - len(k_padded))
        print("%s %s" % (k_padded, namespaces[k]))

    print("\n--- Environment ---")
    environ = read_file("/proc/self/environ")
    env_vars = [e for e in environ.split("\x00") if e]
    print("%d environment variables loaded." % len(env_vars))

    print("==================================================")
    return "OK"
```

### Critical Fields Explained

#### `agent_config.type`

Must be either `"coff"` (for BOFs) or `"starlark"`.

#### `agent_config.files`

An array of relative paths (relative to the directory where `config.json` lives) pointing to the compiled payloads or script files.

- For BOFs, provide the `.x64.o` and `.x86.o` compiled object files. The agent will dynamically load the correct architecture file at runtime.
- For starlark modules, `files[0]` is the entry-point script; every other entry is a **companion file** that is uploaded to the agent and cached in encrypted memfs (`mem:///`) before the script runs. The script reads them transparently with `read_file()` and can enumerate them via the `module_files` global. This is enabled per-module by setting `"module_files_memfs": true` in the module's own `config.json` (off by default). See `core/modules/kkyum/` for an example: `kkyum.star` loads the companion kernel-driver `.sys` from memfs with `driver_load_bytes`.

#### `parameters`

This defines the CLI flags the operator can use (e.g. `--pid 1234`).
**CRITICAL:** For BOF modules, the `type` field dictates exactly how the C2 packs the arguments into the wire format before sending them to the agent! Based on the C2 parser in `modcustom.go` (`typeToWireToken`), you **must** strictly use one of the following aliases:

- `"int"` (or `"uint32"`, `"dword"`): Packed as a 32-bit integer (`'i'`).
- `"short"` (or `"word"`, `"int16"`): Packed as a 16-bit short (`'s'`).
- `"cstr"` (or `"string"`): Packed as a UTF-8 C-String (`'z'`).
- `"wstr"` (or `"wstring"`): Packed as a UTF-16LE Wide String (`'Z'`).
- `"binary"` (or `"base64"`, `"b"`): Packed as a length-prefixed binary blob (`'b'`).

_Note: Never use arbitrary strings like `"integer"` or `"file"`, as the COFF packer will fail to identify the type and abort the execution._
_Note 2: Do not use reserved flags like `"force"` or `"help"` as parameter names, as they conflict with internal Cobra CLI flags._

---

## 3. Build Automation (`make_all.sh`)

emp3r0r features a dynamic, generic build system. You **do not** need to edit `core/build.sh` when adding a new module suite.

If your module requires compilation (e.g., compiling C code to BOF `.o` files), simply create an executable bash script named `make_all.sh` at the root of your module directory:

`core/modules/MyModuleSuite/make_all.sh`:

```bash
#!/bin/bash
set -e
echo "[*] Building MyModuleSuite..."

# Example: invoke Makefiles in subdirectories
make -C src/MyBof -j$(nproc)
```

Ensure the script is executable (`chmod +x make_all.sh`). During the global compilation process (`./core/build.sh`), the main script will automatically detect any `make_all.sh` files in the `core/modules/*` directories and execute them seamlessly.

_(Remember: Keep compiled `.o` files in their respective source directories. Do not copy them out of the source tree; simply reference their relative paths in `config.json`'s `files` array!)_

---

## 4. How the C2 Loads Your Module

When the emp3r0r C2 starts, it parses the modules via `InitModules` in `core/internal/cc/modules/modcustom.go`:

1. **Discovery:** Scans `modules/*` directories for `config.json` files.
2. **Validation:** Unmarshals the JSON. If there are duplicate parameter names, reserved flags (`force`, `help`), or schema errors, it throws a warning and skips the module.
3. **Registration:** Stores the valid module into the `def.Modules` memory map.
4. **Execution:** When the operator runs your module, `moduleCustom` reads the operator's input, validates it against your `parameters`, packs it according to the `type` aliases, and dispatches the task down to the agent memory for fileless execution.

_Note: For BOFs, only the arch-matching file from the `files` list is executed (e.g. only the `.x64.o` when the target is amd64). For starlark modules, `files[0]` is the entry point and the rest are memfs companion files (see `agent_config.files` above)._

---

## 5. Starlark Module Scripting & API Reference

emp3r0r includes a high-performance, embedded Starlark script engine for cross-platform and Windows/Linux native system scripting.

### Critical Rules & Differences from Python

> [!IMPORTANT]
> **Starlark is NOT Python!**
>
> - Starlark does **not** have Python's standard library (do not `import sys`, `import re`, `import math`, etc.).
> - Standard Python functions like `hex()` or advanced `%016x`, `%-30s` format specifiers in `%` string formatting are **not** built into standard Starlark.
> - **Use the Go-Native APIs**: Use the native built-in APIs provided by the engine (`sprintf`, `hex`, `read_uint32`, `read_wstring`, `utf16_ptr`, `str_split`, etc.) for maximum performance and safety.

### Starlark Built-in API Reference

#### A. String Formatting & Manipulation

| API Function                      | Parameters               | Description                                                                                      |
| :-------------------------------- | :----------------------- | :----------------------------------------------------------------------------------------------- |
| `sprintf`                         | `(format_string, *args)` | Formats a string using Go `fmt.Sprintf` format specifiers (`%016x`, `%02d`, `%-30s`, `%+03d`).   |
| `hex`                             | `(val)`                  | Converts an integer value to a `0x...` hexadecimal string.                                       |
| `str_split`                       | `(s, sep)`               | Splits string `s` by separator `sep` into a list of strings.                                     |
| `str_join`                        | `(elements, sep)`        | Joins an iterable list/tuple of strings with separator `sep`.                                    |
| `str_replace`                     | `(s, old, new, n=-1)`    | Replaces occurrences of `old` with `new` in string `s`.                                          |
| `str_contains`                    | `(s, substr)`            | Returns `True` if `substr` is inside `s`, `False` otherwise.                                     |
| `str_trim`                        | `(s, cutset="")`         | Trims leading and trailing whitespace or characters in `cutset`.                                 |
| `str_lower` / `str_upper`         | `(s)`                    | Returns lowercase or uppercase representation of string `s`.                                     |
| `str_startswith` / `str_endswith` | `(s, prefix/suffix)`     | Returns `True` if string `s` starts with `prefix` or ends with `suffix`.                         |
| `str_pad` / `pad`                 | `(text, width)`          | Pads `text` to specified column width (right-padded if `width > 0`, left-padded if `width < 0`). |
| `str_index`                       | `(s, substr)`            | Returns the zero-based index of `substr` in `s`, or `-1` if not found.                           |

#### B. Memory Reading Primitives (Go Native)

All memory reading primitives safely access unmanaged memory addresses across Windows and Linux processes.

| API Function                            | Parameters           | Description                                                                                   |
| :-------------------------------------- | :------------------- | :-------------------------------------------------------------------------------------------- |
| `read_u8` / `read_uint8`                | `(addr, offset=0)`   | Reads 1 byte (`uint8`) from `addr + offset`.                                                  |
| `read_u16` / `read_uint16`              | `(addr, offset=0)`   | Reads 2 bytes (`uint16`, little-endian) from `addr + offset`.                                 |
| `read_u32` / `read_uint32`              | `(addr, offset=0)`   | Reads 4 bytes (`uint32`, little-endian) from `addr + offset`.                                 |
| `read_u64` / `read_uint64` / `read_ptr` | `(addr, offset=0)`   | Reads 8 bytes (`uint64`/pointer, little-endian) from `addr + offset`.                         |
| `read_i32` / `read_int32`               | `(addr, offset=0)`   | Reads signed 4 bytes (`int32`, little-endian) from `addr + offset`.                           |
| `read_wstring`                          | `(ptr, max_len=256)` | Safely reads a null-terminated UTF-16 wide string from memory pointer into a Starlark string. |
| `read_cstring` / `read_ansi_string`     | `(ptr, max_len=256)` | Safely reads a null-terminated C/ANSI string from memory pointer into a Starlark string.      |

#### C. Memory Writing Primitives & String Allocators

| API Function                               | Parameters                | Description                                                                                                         |
| :----------------------------------------- | :------------------------ | :------------------------------------------------------------------------------------------------------------------ |
| `write_byte` / `write_u8`                  | `(addr, [offset=0,] val)` | Writes 1 byte to target memory address `addr + offset`.                                                             |
| `write_u16` / `write_uint16`               | `(addr, [offset=0,] val)` | Writes 2 bytes (`uint16`, little-endian) to `addr + offset`.                                                        |
| `write_u32` / `write_uint32`               | `(addr, [offset=0,] val)` | Writes 4 bytes (`uint32`, little-endian) to `addr + offset`.                                                        |
| `write_u64` / `write_uint64` / `write_ptr` | `(addr, [offset=0,] val)` | Writes 8 bytes (`uint64`/pointer, little-endian) to `addr + offset`.                                                |
| `utf16_ptr`                                | `(s)`                     | Allocates unmanaged memory, encodes string `s` to UTF-16LE null-terminated, and returns memory address pointer.     |
| `cstring_ptr` / `ansi_ptr`                 | `(s)`                     | Allocates unmanaged memory, encodes string `s` to null-terminated C/ANSI bytes, and returns memory address pointer. |

#### D. Windows & Linux System Interop

| API Function                                       | Parameters                    | Description                                                                                                                   |
| :------------------------------------------------- | :---------------------------- | :---------------------------------------------------------------------------------------------------------------------------- |
| `win_call`                                         | `(dll, function_name, *args)` | Dynamically calls an exported Windows DLL function with native parameters. Returns dict with `r1`, `r2`, `err_code`, `error`. |
| `win_alloc` / `win_free`                           | `(size)` / `(addr)`           | Allocates / frees unmanaged memory on Windows via `VirtualAlloc`/`VirtualFree`. Passing `0` to `win_free` is safely ignored.  |
| `win_read_mem`                                     | `(addr, size)`                | Reads raw memory byte list from Windows process memory via `ReadProcessMemory`.                                               |
| `sys_call` / `lin_syscall` / `linux_syscall`       | `(syscall_num, *args)`        | Executes a native Linux syscall.                                                                                              |
| `sys_alloc` / `lin_alloc` / `linux_alloc`          | `(size)`                      | Linux memory allocation via `mmap`. Returns base memory address.                                                              |
| `sys_free` / `lin_free` / `linux_free`             | `(addr)`                      | Deallocates memory allocated on Linux.                                                                                        |
| `sys_read_mem` / `lin_read_mem` / `linux_read_mem` | `(addr, size)`                | Reads raw memory byte list from Linux process memory.                                                                         |

#### E. File System, Networking, Execution & Cryptography

| API Function                               | Parameters                   | Description                                                                                |
| :----------------------------------------- | :--------------------------- | :----------------------------------------------------------------------------------------- |
| `read_file` / `write_file`                 | `(path)` / `(path, content)` | File reading and writing.                                                                  |
| `list_dir` / `exists` / `mkdir` / `remove` | `(path)`                     | Directory listing, existence check, directory creation, and file removal.                  |
| `http_get`                                 | `(url)`                      | Performs HTTP GET request and returns body content string.                                 |
| `http_post`                                | `(url, content_type, body)`  | Performs HTTP POST request and returns body content string.                                |
| `exec_cmd`                                 | `(cmd, args=[])`             | Executes shell command with optional argument string list. Returns combined output string. |
| `crypto_hash`                              | `(algo, data)`               | Computes hash (`"md5"`, `"sha1"`, `"sha256"`) of `data`.                                   |

#### F. Predeclared Global Variables

- **`argv`**: List of string arguments passed to the script execution thread.
- **`current_token`**: Returns a `HANDLE` (as integer) to the current effective token. On Windows this tries the thread token first (so impersonation is visible), then falls back to the process token. Returns `0` on failure. **The caller must close the handle** with `win_call("kernel32.dll", "CloseHandle", h)`.

---

## 6. Token Impersonation (Windows)

emp3r0r supports stealing Windows access tokens from running processes and using them to impersonate users during module execution. This section explains how tokens flow through the system and how to write token-aware modules.

### 6.1 Built-in Token Commands

| Command                             | Description                                                                                                                 |
| ----------------------------------- | --------------------------------------------------------------------------------------------------------------------------- |
| `steal_token --pid <PID>`          | Steal the primary token from a process and cache it. Enables `SeDebugPrivilege` and `SeImpersonatePrivilege` automatically. |
| `list_tokens`                      | List all cached tokens (DOMAIN/User + SID).                                                                                |
| `make_token --user <USER> ...`     | Create a **netlogon logon session** for a domain user using a dummy password (see §6.8).                                   |
| `list_sessions`                    | List all netlogon logon sessions created by `make_token`.                                                                  |
| `import_ticket --session <NAME> ...` | Import a base64 KRB-CRED (.kirbi) Kerberos ticket into a session's logon session (see §6.8).                              |

Every module registered via `config.json` automatically receives three universal parameters:

| Parameter    | Meaning                                                                                                                 |
| ------------ | ----------------------------------------------------------------------------------------------------------------------- |
| `--token`    | SID of a stolen token (`list_tokens`) **or** a make_token session name (`list_sessions`) to impersonate.               |
| `--user`     | Create/reuse a make_token netlogon session for this user (`DOMAIN/user` or plain) and run the module under it.          |
| `--ticket`   | Base64 KRB-CRED (.kirbi) to import into the module's logon session (the `--token`/`--user` session, or the current one). |

`--user` is ignored when `--token` is set. If a module declares its own `user`/`ticket` parameter in `config.json`, that declaration wins and the universal meaning is disabled for that module.

### 6.2 How Token Impersonation Works

```
ModuleHandler
  executeWithToken(sid, func(token uintptr) error {
    // token = raw HANDLE from TokenMap, or 0 if no token set
    ...
  })
```

For **starlark modules**, each I/O builtin wraps itself with `runWithToken`:

```
starlarkReadFile(thread, ...)
  runWithToken(thread, func() error {
    1. LockOSThread()
    2. NtSetInformationThread(ThreadImpersonationToken)  ← indirect syscall
    3. os.ReadFile(path)     ← file opened with stolen identity
    4. NtSetInformationThread(nil)   ← revert
    5. UnlockOSThread()
  })
```

This means **every** `read_file`, `write_file`, `list_dir`, `exists`, `mkdir`, `remove`, `win_call`, `win_alloc`, `win_free`, `win_read_mem`, `http_get`, `http_post` and `exec_cmd` call automatically runs under the stolen token when one is assigned. No extra code is needed in the starlark script.

### 6.3 Using `current_token()` in Starlark Scripts

When a script needs to inspect the effective identity (e.g. for whoami-style output or to pass the token to a Win32 API that requires a token handle), use the `current_token()` builtin:

```python
def example_whoami():
    TOKEN_QUERY = 0x0008

    # Returns a handle to the current effective token.
    # If a token was stolen and assigned to this module, this IS the stolen token.
    h_token = current_token()
    if h_token == 0:
        print("[-] Failed to open current token")
        return

    # Query token information (example: TokenUser)
    TOKEN_INFORMATION_CLASS_TokenUser = 1
    req_size_ptr = win_alloc(4)
    win_call("advapi32.dll", "GetTokenInformation", h_token,
             TOKEN_INFORMATION_CLASS_TokenUser, 0, 0, req_size_ptr)
    req_size = read_uint32(req_size_ptr, 0)

    token_user_buf = win_alloc(req_size)
    win_call("advapi32.dll", "GetTokenInformation", h_token,
             TOKEN_INFORMATION_CLASS_TokenUser, token_user_buf, req_size, req_size_ptr)

    # ... parse TOKEN_USER, resolve SID, etc.

    # Always close the handle when done.
    win_call("kernel32.dll", "CloseHandle", h_token)
```

> **Important**: Always `CloseHandle` the token handle returned by `current_token()`. Each call returns a new handle.

### 6.4 Token-Aware Script Examples

See these reference implementations:

| Script                                  | What it demonstrates                                                          |
| --------------------------------------- | ----------------------------------------------------------------------------- |
| `core/modules/SA/whoami.star`           | Full token inspection: user, groups, privileges. Thread-token-first fallback. |
| `core/modules/injection/thread_inject.star` | Remote thread injection under the operator-selected token.          |
| `core/modules/SA/get_dpapi_system.star` | Checking token elevation before attempting LSA secret extraction.             |

### 6.5 COFF (BOF) Modules and Tokens

COFF/BOF payloads run in-process on a dedicated goroutine. When a token is assigned:

1. The token handle is stored before the BOF goroutine starts.
2. `PreExecHook` fires on the BOF goroutine: `LockOSThread` + `NtSetInformationThread(token)`.
3. The BOF entry point (`syscall.SyscallN`) executes — any Win32 APIs called by the BOF see the impersonated identity.
4. `PostExecHook` fires: `NtSetInformationThread(nil)` + `UnlockOSThread`.

No changes are needed in the BOF source code.

### 6.6 Limitations

| Module type    | Token support | Notes                                                                                                   |
| -------------- | ------------- | ------------------------------------------------------------------------------------------------------- |
| **starlark**   | Full          | Every I/O builtin impersonates independently. `exec_cmd` spawns children via `CreateProcessWithTokenW`. |
| **coff (BOF)** | Full          | Pre/post-exec hooks impersonate the BOF goroutine.                                                      |
| **powershell** | None          | `exec.Command` cannot use thread tokens. A warning is logged if a token is assigned.                    |
| **bash**       | None          | Same limitation as powershell.                                                                          |
| **python**     | None          | Same limitation as powershell.                                                                          |

> **Recommendation**: Use **starlark modules** for any token-aware operations. The starlark `win_call` builtin gives you direct access to the full Win32 API under the stolen identity.

### 6.7 Privilege Requirements

`steal_token` automatically enables:

- `SeDebugPrivilege` — required to open handles to most processes (especially SYSTEM-level).
- `SeImpersonatePrivilege` — required to set thread tokens and spawn children via `CreateProcessWithTokenW`.

If the agent does not hold these privileges (e.g. running as a low-privilege user), warnings are logged and token operations will fail with `STATUS_ACCESS_DENIED`.

### 6.8 Netlogon Logon Sessions (`make_token`) and Kerberos Tickets

Thread impersonation alone is not enough for Kerberos: `ptt`, `asktgt /ptt`, `klist`, … talk to LSA and are bound to a **logon session** (the `AuthenticationId`/LUID registered in LSASS), not to a token. BOFs/starlark modules are token-aware, so without a matching logon session ticket imports fail (`STATUS_ACCESS_DENIED`/`0xC0000022` or the ticket simply not showing up in `klist`).

`make_token` solves this by creating a **netonly netlogon (new-credentials) logon session** (the same primitive Cobalt Strike's `make_token` / `runas /netonly` use):

```
make_token --user jdoe --domain corp.local --password dummy --name jdoe
# → session name: jdoe, logon LUID: 0x12345678
```

Internally it calls `LogonUserW(user, domain, any_password, LOGON32_LOGON_NEW_CREDENTIALS, LOGON32_PROVIDER_WINNT50)`, which registers a brand-new logon session in LSASS. **The password is never validated** — any value (or none) works. Because this is a *new-credentials* (netonly) logon, the session token keeps the **calling user's local identity** (`whoami` is unchanged) and the supplied credentials are used only for outbound network connections; what the session gives you is a fresh `AuthenticationId` (LUID) that Kerberos tickets can be bound to. The session is cached agent-side (`priv.SessionMap`) and its token is registered in `priv.TokenMap` under the session name, so **the universal `--token <session>` parameter works for any BOF/starlark module**.

Typical Kerberos workflow:

1. `make_token --user jdoe --domain corp.local --password x` — create the session.
2. `import_ticket --session jdoe --ticket <base64 kirbi>` — import a TGT/TGS into the session's logon session via `LsaCallAuthenticationPackage(KerbSubmitTicketMessage)` (the same mechanism as the Kerbeus `ptt` BOF, implemented in-process — no BOF needed). The session token is impersonated while LSA runs, so `SeImpersonatePrivilege` (not SYSTEM) is sufficient.
3. Run ticket-bound BOFs/starlark modules under the session:
   - `kerbeus_asktgt --params '/user:jdoe ... /ptt' --token jdoe`
   - `kerbeus_ptt --params '/ticket:...' --token jdoe` (imports into the impersonated session; `/luid:` optional)
   - any starlark module with `--token jdoe`
4. `list_sessions` — list all sessions (name, user, LUID).

The universal `--user`/`--ticket` options let you skip the manual two-step setup — the agent creates the session and imports the ticket as part of the module invocation:

```
kerbeus_klist --user jdoe --ticket <base64 TGT> --token jdoe
# or, session created on the fly (no --token needed):
kerbeus_klist --user CORP.LOCAL/jdoe --ticket <base64 TGT>
```

Notes:

- After `import_ticket`, outbound network access (SMB shares, RPC, …) under the session authenticates **with the imported Kerberos ticket** — this is the pass-the-ticket flow: `make_token` is the container, the ticket is the identity. Without an imported ticket, network access falls back to the netonly credentials (a dummy password then yields `ERROR_LOGON_FAILURE (1326)` on network resources, as with Cobalt Strike's `make_token`).
- `whoami`/token-identity BOFs still report the *current* user: the netonly token's SID never changes (PTT changes network identity, not the token SID) — exactly as with Cobalt Strike's `make_token`/`ptt`.
- `import_ticket --luid <hex> --ticket <b64>` targets an explicit logon session LUID (as printed by `list_sessions`); importing into a session owned by another user requires SYSTEM.
- `list_tokens` also shows make_token sessions (annotated with `[make_token session]`), and the `--token`/`--session` completers offer both SIDs and session names.
- The session token is an impersonation duplicate of the logon token; it remains valid until the agent exits or the session is recreated under the same name.

---

#### G. Agent Interop & Proxy APIs (`agent.*` / `agent_*`)

| API Function / Method                             | Parameters                                          | Description                                                                                                       |
| :------------------------------------------------ | :-------------------------------------------------- | :---------------------------------------------------------------------------------------------------------------- |
| `agent.sys_info` / `agent_sys_info`               | `()`                                                | Returns a dictionary containing system details (`tag`, `uuid`, `os`, `user`, `has_root`, `process`, `cwd`, etc.). |
| `agent.uptime` / `agent_uptime`                   | `()`                                                | Returns target system uptime string.                                                                              |
| `agent.user` / `agent_user`                       | `()`                                                | Returns dictionary with `user` and `groups` strings.                                                              |
| `agent.container` / `agent_container`             | `()`                                                | Returns container runtime environment if running inside a container, or empty string.                             |
| `agent.has_root` / `agent_has_root`               | `()`                                                | Returns `True` if running with root privileges, `False` otherwise.                                                |
| `agent.exec_shell` / `agent_exec_shell`           | `(script, args=[], env=[])`                         | Executes shell script in memory.                                                                                  |
| `agent.exec_python` / `agent_exec_python`         | `(script, args=[], env=[])`                         | Executes Python script in memory.                                                                                 |
| `agent.exec_powershell` / `agent_exec_powershell` | `(script, args=[], env=[])`                         | Executes PowerShell script in memory on Windows targets.                                                          |
| `agent.exec_batch` / `agent_exec_batch`           | `(script, args=[], env=[])`                         | Executes Batch script in memory on Windows targets.                                                               |
| `agent.sign` / `agent_sign`                       | `(data)`                                            | Signs data string or bytes with agent's ephemeral private key.                                                    |
| `agent.tag` / `agent_tag`                         | `()`                                                | Returns agent tag string.                                                                                         |
| `agent.uuid` / `agent_uuid`                       | `()`                                                | Returns agent UUID string.                                                                                        |
| `agent.touch_file` / `agent_touch_file`           | `(path)`                                            | Restores/synchronizes timestamps on target file.                                                                  |
| `agent.fetch_file` / `agent_fetch_file`           | `(file_to_download, peer="", path="", checksum="")` | Downloads file via memfs/P2P/C2 pipeline. Returns bytes if `path` is empty, or saves to `path`.                   |
