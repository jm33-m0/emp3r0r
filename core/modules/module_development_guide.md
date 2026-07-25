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

_Note: Currently, only the first file in the `files` list is executed, which in most cases means only `x64` BOFs are picked up._

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
