# Vendored miniz (self-contained gzip)

Single-file amalgamation of [miniz](https://github.com/richgel999/miniz) used by
`src/gzip/miniz.c` for gzip compression/decompression.

- Upstream: https://github.com/richgel999/miniz
- Version: **3.1.2**
- License: MIT (see `LICENSE`)

Only the `tdefl`/`tinfl` (DEFLATE/INFLATE) APIs are compiled in; the archive
reader and the zlib compatibility shim are disabled via the `MINIZ_NO_*`
defines in `core/c_agent/Makefile`. That keeps the agent free of any system
zlib dependency.

## Regenerating the amalgamation

```sh
git clone --depth 1 --branch 3.1.2 https://github.com/richgel999/miniz.git
cd miniz && cmake -H. -B_build -DAMALGAMATE_SOURCES=ON -G "Unix Makefiles"
cp _build/amalgamation/miniz.c _build/amalgamation/miniz.h <dest>/
```

(The upstream `amalgamate.sh` also runs optional compiler smoke tests and zips
the result; only the two amalgamated files are vendored here.)
