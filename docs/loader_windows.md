# loader_windows internals

`loader_windows` is a local module that builds a self-unpacking Windows loader
from a Donut sRDI shellcode blob. Operator help is in the module manifest:
`run_module` with `module=loader_windows`, or `module_help` over MCP.

## Source layout

- `bootstrap.c` / `bootstrap.h` — host container entry, service control, and
  the early-bird injection sequence.
- `loader.c`, `reflect.c`, `reflect.h` — reflective DLL mapping and export
  resolution for the encrypted payload.
- `stager.c`, `pack.c` — payload decryption and stage handoff.
- `dllhost.c` — DLL host that exports `Run()`.
- `config.h`, `config.json` — compile-time defaults and module metadata.
- `stage_abi.h`, `stage_data.h` — ABI shared with the packed stage.
- `build.sh` — the build contract used by `run_module`.

Shared sources are mirrored into the operator workspace next to the module:
RC4 from `core/c_agent/`, `ntsys` and SilentMoonwalk from `core/modules/common/`.

## Build contract

`build.sh` accepts the flags declared in `config.json` and writes exactly one
artifact. The module runner passes every non-internal flag through unchanged, so
a new option must be added to both `config.json` and `build.sh`, with a matching
`--flag` case in the parser.

The host is always built in two layers: the loader DLL is RC4-encrypted and
embedded in the host with `.incbin` through `stage_data.S`. `format` selects the
host container (`service`, `exe`, or `dll`). Keep the `.incbin` approach rather
than RCDATA so the DLL form still works when mapped in memory.

`nasm` is required for the default SilentMoonwalk path on x64. `smw=off` must
remain a build without that dependency.

## Extending

- New container: add a format branch to `build.sh`, a `choices` entry in
  `config.json`, and the matching host entry point.
- New injection method: add the implementation under `bootstrap.c`, validate it
  in the `--inject` parser, and extend the choice list.
- New masking or packing step: keep it symmetric with the unpack path in
  `stager.c`; an asymmetric change produces a loader that injects but never
  starts.

## Verification

The build result is the deliverable. Do not execute it on the operator host.
Verify by inspecting the returned path and size, and by running the artifact on
a disposable Windows target. `--verify-ms` controls the loader's own post-
injection check.
