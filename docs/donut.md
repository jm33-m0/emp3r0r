# Donut shellcode producer

The `donut` module builds Donut from the source vendored under
`core/modules/donut/src` and converts a Windows PE into position-independent
shellcode. It runs on the C2 as a local module.

## Prerequisites

- `zig` on `PATH`, or `ZIG=/path/to/zig`. emp3r0r installs zig for module
  builds; the builder image also carries it.
- No external Donut binary is used. The loader stubs and the generator are
  rebuilt on every invocation.

## Source layout

| Path | Purpose |
| --- | --- |
| `src/donut.c` | generator entry and shellcode layout |
| `src/loader/` | freestanding Windows loader stub (injection, AMSI/ETW bypass, PE mapping) |
| `src/loader/exe2h/` | converts a stub's `.text` section into the generated headers |
| `src/lib/aplib64.a` | upstream aPLib archive used by the generator |
| `src/loader/mem_shim.c` | local freestanding `memcpy`/`memset`/`memmove` shim |

`build.sh` builds the x86 and x64 stubs with
`-target {x86,x86_64}-windows-gnu -nostdlib`, regenerates
`loader_exe_{x86,x64}.h`, then builds the Linux generator and runs it. Because
it compiles `src/loader` directly, editing the loader changes the generated
shellcode on the next build.

## Usage

```text
donut --input /path/to/agent.exe
donut --input /path/to/agent.exe --output /path/to/agent.donut.bin
donut --input /path/to/postex.dll --arch 2 --entropy 3 --compression 2 --bypass 3
```

The default output is `<input>.donut.bin`, so it never overwrites the input or
the agent's own `.bin` shellcode.

## Options

| Option | Values | Default | Meaning |
| --- | --- | --- | --- |
| `--input` | path | required | Windows PE (EXE/DLL) to convert |
| `--output` | path | `<input>.donut.bin` | Output shellcode |
| `--arch` | `1`, `2`, `3` | `2` | x86, amd64, or both |
| `--entropy` | `1`, `2`, `3` | `3` | Names only, random names, random names and encryption |
| `--compression` | `1`, `2`, `3` | `2` | None, aPLib, LZNT1 |
| `--bypass` | `1`, `2`, `3` | `3` | AMSI/WLDP: none, abort, continue |
| `--decoy` | path | unset | Decoy module for module overloading; must be a regular file in the operator payload directory |
| `--method` | name | unset | Entrypoint method for a DLL |
| `--params` | string | unset | Payload command-line parameters |
| `--run-thread` | `0`, `1` | `1` | Run the entrypoint in a new thread |
| `--exit` | `1`, `2`, `3` | `1` | Exit thread, exit process, or block |

The options are declared in `config.json` and validated twice: by the C2 before
the build, and again in `build.sh`.

## Detection loop

The autonomous loop can edit this module and rebuild the shellcode:

```bash
detect_loop --module-dir /path/to/core/modules/loader_windows \
  --producer donut=/path/to/core/modules/donut --iterations 6
```

`BuildShellcode` accepts the options above, writes the artifact under the
detection store, and makes it the shellcode for every later cycle. The input is
limited to PE files in the operator payload directory. `--decoy` is the
supported way to test Donut's module-overloading path.

When a loader-only edit cannot remove a signature that lives in the generated
blob, edit the producer source instead of reworking the loader. The loop sees
the vendored tree as the `donut` module, so `EditSource` with `module=donut`
can change `src/loader/*.c`, `src/donut.c`, or the headers, and the next
`BuildShellcode` recompiles the stub from that source.
