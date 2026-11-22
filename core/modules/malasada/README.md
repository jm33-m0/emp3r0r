# malasada

The Linux shellcode producer. It converts an ELF shared object into a
position-independent blob: a 64-bit stage0 loader followed by the original
shared object (optionally aPLib-compressed).

The converter is Go source under `src/`, vendored from
[sliverarmory/malasada](https://github.com/sliverarmory/malasada) with the local
`go-keystone` and `wazero` packages under `src/third_party/`. A build compiles
the current tree, so a detection-loop edit to `src/` changes the next blob.

## Inputs

| Option | Default | Purpose |
| --- | --- | --- |
| `input` | required | Linux ELF shared object (`ET_DYN`, `.so`) |
| `output` | `<input>.malasada.bin` | raw PIC output |
| `call-export` | `main` | exported symbol the stage0 stub calls |
| `compress` | `on` | aPLib-compress the shared object |

The producer prints the standard `generated payload` marker. `core/build.py`
copies the Go toolchain into the operator kit as `lib/emp3r0r/go`; `build.sh`
uses it when present and otherwise falls back to `go` on `PATH`. Set `GO` to
override.
