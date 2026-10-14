# Vendored mbedTLS (self-contained crypto/TLS fallback)

This directory is a **pruned** copy of the upstream mbedTLS release used by the
C agent when the target has no system crypto/TLS library (`libcrypto`). The
OpenSSL backend in `src/c2_crypto_openssl.c` is preferred when libcrypto can be
loaded; this one guarantees the agent still runs without it.

- Upstream: https://github.com/Mbed-TLS/mbedtls
- Version: **3.6.7** (LTS), tag `v3.6.7`
- License: Apache-2.0 (see `LICENSE`)

## What is kept

Only what `library/Makefile` needs to build `libmbedcrypto.a` (AEAD, hashes,
KDFs, P-256) and `libmbedtls.a` (TLS 1.3 client):

```
include/            public headers
library/            sources, Makefile and pre-generated files
3rdparty/           everest + p256-m (referenced by the build)
scripts/            mbedTLS code generators the Makefile depends on
framework/scripts/  mbedTLS-framework generators (ssl_debug_helpers)
framework/exported.make
LICENSE
```

`tests/`, `programs/`, `docs/`, `.github/`, `cmake/`, `configs/` and the
framework's tests/docs are deliberately omitted. The pre-generated sources
shipped in the release (`error.c`, `version_features.c`,
`ssl_debug_helpers_generated.c`, the PSA driver wrappers) are kept as-is, so a
build does not regenerate them.

## Build

```sh
make -C core/c_agent vendor-mbedtls   # builds library/libmbedcrypto.a and libmbedtls.a
```

The `library/Makefile` applies a config header. To shrink the build further, a
project config can be injected with `MBEDTLS_CONFIG_FILE`; the default upstream
config is used today.

## Updating

Replace the tree with a new release and keep the same layout:

1. Download `https://github.com/Mbed-TLS/mbedtls/archive/refs/tags/vX.Y.Z.tar.gz`
   and copy `include/ library/ 3rdparty/ scripts/` plus `LICENSE`.
2. Copy `framework/scripts/` and `framework/exported.make` from the
   `mbedtls-framework` commit pinned by `mbedtls/.gitmodules`
   (v3.6.7 pins `dde0c4a0e448a0552f18817dcea633bb851fd288`).
3. Delete any `*.o`/`*.a` build artifacts and update the version above.

The two build products are gitignored; only source is tracked.
