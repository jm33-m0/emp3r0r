# Linux SA BOFs

Linux x86_64 SA BOFs from [TrustedSec ELFLoader](https://github.com/trustedsec/ELFLoader),
vendored under the upstream BSD license in `LICENSE.txt`.

The BOFs are built against glibc 2.17 headers so their `struct stat` layout
matches the loader's glibc runtime; a statically linked or musl-only agent
cannot resolve these libc symbols. The upstream loader and runner are not
included: emp3r0r uses its own `coffloader_linux` dependency.
