# stager_linux internals

`stager_linux` builds a Linux stager for a C agent PIC. Operator help is in the
module manifest: `run_module` with `module=stager_linux`, or `module_help` over
MCP.

## Source layout

- `stub.c`, `stager_pic.ld` — freestanding PIC entry and linker script.
- `downloader.c`, `transport_http.c`, `transport_tcp.c`, `transport_udp.c`,
  `transport_libcurl.c`, `transport_libssl.c`, `transport.h` — payload
  download providers.
- `mask.c`, `mask.h`, `mask_ranges.h`, `mask_xor.c` — sleep mask.
- `unpack_stub_rc4.c`, `unpack_stub_lzss.c`, `unpack.h`, `lzss.h` — packed
  shellcode unpackers.
- `stager_state.c`, `state.h`, `supervise.h` — supervisor state.
- `embed_payload.py`, `pack_common.py`, `pack_rc4.py`, `pack_lzss.py` — build
  helpers.
- `build.sh`, `Makefile`, `config.json` — build contract and module metadata.

## Build contract

`build.sh` parses the flags declared in `config.json` and invokes `make` with
the resulting variables. Keep the parser, `Makefile`, and `config.json` in
sync: the module runner forwards supplied flags only, and defaults live in all
three places.

- `format=raw` is PIC shellcode for a loader; `packed` is self-unpacking
  shellcode; `executable` is a linked ELF; `so` is a shared object.
- Embed mode activates when `agent-pic` is set and ignores every `payload-*`
  option. Download mode requires the listener options to match
  `emp3r0r-listener`.
- `unpacker` selects the RC4 or LZSS stub. Keep both stubs symmetric with the
  packers; a mismatch yields a stager that downloads but never starts.
- `dynload-mode` selects the glibc ABI (`public` for 2.34+, `libc_dl` for older
  glibc). `hash-style` must match the target loader.
- `supervise` requires a stager-built agent so identity survives restarts.

## Tests

`tests/` contains the stager lifecycle, packer, transport, C agent, sleep mask,
and SOCKS5 end-to-end tests. `test/` holds the harness shared with the Go
tests. Run them with `make -C core/modules/stager_linux test`, or the package
test that covers the changed path.

The build result is the deliverable. Do not execute it on the operator host;
verify by inspecting the returned path and size.
