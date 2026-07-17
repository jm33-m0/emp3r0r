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

```json
[
  {
    "name": "my_suite_process_list",
    "author": "YourName",
    "date": "2026-07-17",
    "comment": "Lists processes using a Beacon Object File.",
    "platform": "Windows",
    "is_local": false,
    "fileless": true,
    "agent_config": {
      "type": "coff",
      "files": ["src/MyBof/MyBof.x64.o", "src/MyBof/MyBof.x86.o"],
      "in_memory": true,
      "interactive": false
    },
    "invocation": {
      "coff_export": "go"
    },
    "parameters": [
      {
        "name": "pid",
        "description": "Target Process ID to inspect",
        "default": "0",
        "type": "int",
        "required": true
      },
      {
        "name": "filter",
        "description": "String filter to match",
        "default": "",
        "type": "cstr",
        "required": false
      }
    ]
  }
]
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

_Note: Currently only the first file in the `files` list is executed, which in most cases means only `x64` BOFs are picked up._
