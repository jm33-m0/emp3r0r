# Vendored mini-rv32ima

Single-header RV32IMA interpreter used by `rvvm_linux`.

- Upstream: https://github.com/cnlohr/mini-rv32ima
- Commit: `5f2ece1c5df38b7ca24f6a01df4a9d2bca9fa1a3`
- File: `mini-rv32ima/mini-rv32ima.h` (548 lines)
- SHA-256: `049b916d9ad628fbe9f67fd3401412c0100b0369efc93acdf81c0c0d51293dc1`
- License: MIT (the header additionally offers BSD and CC0; see `LICENSE`)

The file is vendored verbatim. `../../rvvm.c` includes it once with
`MINIRV32_IMPLEMENTATION` and overrides only the hooks the header documents:

| Macro | Use |
| --- | --- |
| `MINI_RV32_RAM_SIZE` | guest RAM arena size |
| `MINIRV32_RAM_IMAGE_OFFSET` | guest RAM base (`0x80000000`) |
| `MINIRV32_CUSTOM_MEMORY_BUS` | byte-wise, bounds-checked load/store helpers (avoids host alignment/strict-aliasing UB and the 3-byte over-read on instruction fetch at the end of RAM) |
| `MINIRV32_HANDLE_MEM_STORE_CONTROL` / `_LOAD_CONTROL` | MMIO host calls (console, block write, exit) |
| `MINIRV32WARN` / `MINIRV32_POSTEXEC` | compile out upstream logging and per-step callbacks |

`mini-rv32ima` implements RV32IMA (no compressed or floating-point
instructions). BOFs must therefore be built with `-mcpu=generic_rv32`
(RV32I); see `docs/rvvm.md` for the exact object flags.

## Regenerating

```sh
curl -L -o mini-rv32ima.h \
  https://raw.githubusercontent.com/cnlohr/mini-rv32ima/<commit>/mini-rv32ima/mini-rv32ima.h
sha256sum mini-rv32ima.h
```

Do not edit the vendored file. Adapt behaviour through the documented hooks in
`rvvm.c`, so upstream can be re-vendored without a patch queue.
