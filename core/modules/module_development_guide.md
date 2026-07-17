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
    "author": "antigravity",
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
# Starlark scripts receive arguments injected by the agent as global variables
# based on the parameter names defined in config.json.

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
    print("Inheritable:%s" % status.get("CapInh", "N/A"))
    print("Permitted:  %s" % status.get("CapPrm", "N/A"))
    print("Effective:  %s" % status.get("CapEff", "N/A"))
    print("Bounding:   %s" % status.get("CapBnd", "N/A"))
    print("Ambient:    %s" % status.get("CapAmb", "N/A"))
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
        print("%-12s %s" % (k + ":", namespaces[k]))

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
