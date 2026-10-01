# memmod

In-memory shared-library loader: PE DLLs on Windows, ELF `.so` on Linux.

This package is built on the work of two upstream projects:

- **[WireGuard](https://github.com/WireGuard/wireguard-windows)** — original `memmod` PE loader (MIT).
- **[Sliver](https://github.com/BishopFox/sliver) / [sliverarmory/reflektor](https://github.com/sliverarmory/reflektor)** — Linux ELF loader and cross-platform call machinery (MIT; Reflektor's `memmod` is itself a WireGuard fork).

Keep their copyright notices and license text intact when redistributing.
