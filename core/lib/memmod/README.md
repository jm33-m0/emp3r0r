# memmod

In-memory shared-library loader: PE DLLs on Windows, ELF `.so` on Linux.

Lifetime management for loaded dependency images lives one layer up, in
[`core/lib/memdeps`](../memdeps/README.md): it maps a dependency, runs the
operation that needs it, and unmaps before returning, so no DLL/SO stays
resident after its user has finished.

This package is built on the work of two upstream projects:

- **[WireGuard](https://github.com/WireGuard/wireguard-windows)** — original `memmod` PE loader (MIT).
- **[Sliver](https://github.com/BishopFox/sliver) / [sliverarmory/reflektor](https://github.com/sliverarmory/reflektor)** — Linux ELF loader and cross-platform call machinery (MIT; Reflektor's `memmod` is itself a WireGuard fork).

Keep their copyright notices and license text intact when redistributing.
