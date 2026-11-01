# Linux SA BOFs

Linux x86_64 SA BOFs from [TrustedSec ELFLoader](https://github.com/trustedsec/ELFLoader),
vendored under the upstream BSD license in `LICENSE.txt`.

The native BOFs are built against glibc 2.17 headers so their `struct stat`
layout matches the loader's glibc runtime. The `--riscv` variants are compiled
from the same sources against musl and linked into self-contained RV32
executables.

## Portable RISC-V variants

`make` builds `SA/src/*.rv.o` from the same sources; the C2 links them with
RV32 musl into `SA/src/*.rv` executables. Any `sa_linux_*` command can run in
the `rvvm_linux` interpreter with `--riscv`; the C2 recompiles, hosts and
dispatches it automatically. The payloads are architecture-independent, so one
build runs on every Linux agent architecture.

See [`docs/rvvm.md`](../../../docs/rvvm.md) for the build flags and the
supported runtime surface.
