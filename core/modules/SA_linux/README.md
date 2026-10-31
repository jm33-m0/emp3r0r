# Linux SA BOFs

Linux x86_64 SA BOFs from [TrustedSec ELFLoader](https://github.com/trustedsec/ELFLoader),
vendored under the upstream BSD license in `LICENSE.txt`.

The BOFs are built against glibc 2.17 headers so their `struct stat` layout
matches the loader's glibc runtime; a statically linked or musl-only agent
cannot resolve these libc symbols. The upstream loader and runner are not
included: emp3r0r uses its own `coffloader_linux` dependency.

## Portable RISC-V variants

`make` builds `SA/src/*.rv.o` from the same sources. Any `sa_linux_*` command
can run in the `rvvm_linux` interpreter with `--riscv`; the C2 recompiles,
hosts and dispatches it automatically. The payloads are architecture-independent,
so one build runs on every Linux agent architecture. `sa_linux_ifconfig` has no
`_rv` object: the guest runtime does not implement `getifaddrs`.

See [`docs/rvvm.md`](../../../docs/rvvm.md) for the build flags and the
supported runtime surface.
