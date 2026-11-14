# Donut shellcode producer

Local C2 module that builds Donut from the vendored source in `src/` and emits
position-independent shellcode from a Windows PE.

```text
donut --input agent.exe --output agent.exe.donut.bin
donut --input payload.dll --arch 2 --entropy 3 --compression 2 --bypass 3
```

`build.sh` rebuilds three artifacts from source on every invocation:

1. the x86 and x64 freestanding loader stubs (`src/loader`),
2. `exe2h`, which turns each stub's `.text` section into the loader headers,
3. the Linux Donut generator (`src/donut.c`), which emits the shellcode.

The build needs `zig` on `PATH` (or `ZIG=/path/to/zig`). It uses the loader
sources directly, so edits to `src/loader/*.c`, `src/donut.c`, or the generator
headers change the generated shellcode. `src/loader/mem_shim.c` is a local
addition that supplies `memcpy`/`memset`/`memmove` for the freestanding stubs.

Options are declared in `config.json`; the detection loop's `BuildShellcode`
tool validates against the same schema and forces the output under its store.

Upstream source: TheWover/donut v1.1, BSD-3-Clause (see `src/LICENSE`).
See [docs/donut.md](../../../docs/donut.md) for operator usage.
