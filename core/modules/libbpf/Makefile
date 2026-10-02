# Build the libbpf shared object shipped as this module's companion.
#
# Self-contained and reproducible:
#   - every dependency is pinned by version and SHA-256 (libbpf by commit),
#   - everything is compiled with the zig toolchain that ships with emp3r0r,
#   - libelf and zlib are statically linked into libbpf.so, so the result
#     depends only on libc.
#
# The C2 runs this on every module invocation; the build is idempotent and
# reuses any artifact that already exists.
#
# libbpf is built for the host architecture by default, pinned to glibc
# 2.17 to match the manylinux2014 builder image and the oldest supported
# targets. Zig's unversioned `x86_64-linux-gnu` default is glibc 2.31, which
# would not load on CentOS 7 / RHEL 7. Override ZIG_TARGET to cross-build for
# another agent arch, keeping the `.2.17` suffix (e.g. aarch64-linux-gnu.2.17).
LIBBPF_VERSION ?= v1.5.0
LIBBPF_COMMIT  ?= 09b9e83102eb8ab9e540d36b4559c55f3bcdb95d

ZLIB_VERSION := 1.3.1
ZLIB_SHA256  := 9a93b2b7dfdac77ceba5a558a580e74667dd6fede4585b91eefb60f03b72df23
ZLIB_URL     := https://zlib.net/fossils/zlib-$(ZLIB_VERSION).tar.gz

# elfutils provides libelf. Its libelf keeps one __thread variable; we patch it
# to a plain global below so the static library has no native TLS relocations
# (the in-memory loader does not support those).
ELFUTILS_VERSION := 0.188
ELFUTILS_SHA256  := fb8b0e8d0802005b9a309c60c1d8de32dd2951b56f0c3a3cb56d21ce01595dff
ELFUTILS_URL     := https://sourceware.org/elfutils/ftp/$(ELFUTILS_VERSION)/elfutils-$(ELFUTILS_VERSION).tar.bz2

BUILD_DIR ?= .build
DEPS_DIR  := $(BUILD_DIR)/deps
ZLIB_DIR  := $(DEPS_DIR)/zlib
ELF_SRC   := $(DEPS_DIR)/elfutils.src
ELF_DIR   := $(DEPS_DIR)/elfutils
SRC_DIR   := $(BUILD_DIR)/libbpf
LIBSO     := libbpf.so
JOBS      := $(shell nproc 2>/dev/null || echo 2)

# emp3r0r bundles zig; use it instead of requiring a system toolchain.
ZIG    ?= zig
ZIG_TARGET ?= x86_64-linux-gnu.2.17
# libbpf probes the target arch with `$(CC) -dumpmachine`, but zig rejects the
# versioned triple there and logs a spurious error. The result only chooses
# lib/ vs lib64/ for install paths, so derive it from ZIG_TARGET directly.
HOSTARCH := $(firstword $(subst -, ,$(ZIG_TARGET)))
CC     := $(ZIG) cc -target $(ZIG_TARGET)
AR     := $(ZIG) ar
RANLIB := $(ZIG) ranlib

ZLIB_TARBALL := $(BUILD_DIR)/zlib-$(ZLIB_VERSION).tar.gz
ELF_TARBALL  := $(BUILD_DIR)/elfutils-$(ELFUTILS_VERSION).tar.bz2
ZLIB_A       := $(ZLIB_DIR)/lib/libz.a
ELF_A        := $(ELF_DIR)/lib/libelf.a

# zig's clang is stricter than gcc; libbpf's default CFLAGS contain -Werror.
# No -g: debug info embeds absolute build paths and hurts reproducibility.
LIBBPF_CFLAGS := -O2 -Wall -std=gnu89 -Wno-error

.PHONY: all check-deps clean

all: check-deps $(LIBSO)

check-deps:
	@command -v $(ZIG) >/dev/null 2>&1 || { echo "libbpf module: zig not found in PATH"; exit 1; }
	@command -v git >/dev/null 2>&1 || { echo "libbpf module: git not found in PATH"; exit 1; }
	@command -v curl >/dev/null 2>&1 || { echo "libbpf module: curl not found in PATH"; exit 1; }
	@command -v sha256sum >/dev/null 2>&1 || { echo "libbpf module: sha256sum not found in PATH"; exit 1; }
	@command -v tar >/dev/null 2>&1 || { echo "libbpf module: tar not found in PATH"; exit 1; }
	@command -v bzip2 >/dev/null 2>&1 || { echo "libbpf module: bzip2 not found in PATH"; exit 1; }

# ---------------------------------------------------------------------------
# zlib (static, PIC)
# ---------------------------------------------------------------------------

$(ZLIB_TARBALL):
	@mkdir -p $(BUILD_DIR)
	curl -fsSL --retry 3 -o $@ $(ZLIB_URL)
	@echo "$(ZLIB_SHA256)  $@" | sha256sum -c - || { rm -f $@; exit 1; }

$(ZLIB_A): $(ZLIB_TARBALL)
	rm -rf $(ZLIB_DIR) $(ZLIB_DIR).src
	mkdir -p $(ZLIB_DIR).src
	tar -xzf $< -C $(ZLIB_DIR).src --strip-components=1
	cd $(ZLIB_DIR).src && CC='$(CC)' AR='$(AR)' CFLAGS='-O2 -fPIC' \
		./configure --static --prefix=$(abspath $(ZLIB_DIR))
	$(MAKE) -C $(ZLIB_DIR).src -j$(JOBS) install

# ---------------------------------------------------------------------------
# elfutils libelf (static, PIC, no native TLS)
# ---------------------------------------------------------------------------

$(ELF_TARBALL):
	@mkdir -p $(BUILD_DIR)
	curl -fsSL --retry 3 -o $@ $(ELFUTILS_URL)
	@echo "$(ELFUTILS_SHA256)  $@" | sha256sum -c - || { rm -f $@; exit 1; }

$(ELF_A): $(ELF_TARBALL) $(ZLIB_A)
	rm -rf $(ELF_DIR) $(ELF_SRC)
	mkdir -p $(ELF_SRC) $(ELF_DIR)/lib
	tar -xjf $< -C $(ELF_SRC) --strip-components=1
	sed -i 's/static __thread int global_error;/static int global_error;/' $(ELF_SRC)/libelf/elf_error.c
	cd $(ELF_SRC) && CC='$(CC)' AR='$(AR)' RANLIB='$(RANLIB)' \
		CFLAGS='-O2 -fPIC -Wno-error' \
		CPPFLAGS='-I$(abspath $(ZLIB_DIR))/include' \
		LDFLAGS='-L$(abspath $(ZLIB_DIR))/lib' \
		./configure \
			--disable-libdebuginfod --disable-debuginfod \
			--disable-libdw --disable-libdwelf --disable-libdwfl \
			--disable-libasm --disable-libebl --disable-libcpu \
			--disable-nls --with-zlib
	$(MAKE) -C $(ELF_SRC)/lib -j$(JOBS)
	# Only the PIC archive is needed; the shared-object link needs a symbol
	# version script that lld rejects, so build the archive directly.
	$(MAKE) -C $(ELF_SRC)/libelf -j$(JOBS) libelf_pic.a
	cp $(ELF_SRC)/libelf/libelf_pic.a $(ELF_A)

# ---------------------------------------------------------------------------
# libbpf
# ---------------------------------------------------------------------------

$(SRC_DIR):
	@mkdir -p $(BUILD_DIR)
	git clone --depth 1 --branch $(LIBBPF_VERSION) https://github.com/libbpf/libbpf.git $@ || { rm -rf $@; exit 1; }
	cd $@ && test "$$(git rev-parse HEAD)" = "$(LIBBPF_COMMIT)" || \
		{ echo "libbpf module: commit mismatch for $(LIBBPF_VERSION)"; rm -rf $@; exit 1; }

$(LIBSO): $(SRC_DIR) $(ZLIB_A) $(ELF_A) Makefile
	# Force a relink so the strip flag below is always honored; libbpf's make
	# would otherwise treat an existing .so as up to date.
	rm -f $(SRC_DIR)/src/libbpf.so $(SRC_DIR)/src/libbpf.so.*
	$(MAKE) -C $(SRC_DIR)/src -j$(JOBS) \
		CC='$(CC)' \
		AR='$(AR)' \
		HOSTARCH='$(HOSTARCH)' \
		CFLAGS='$(LIBBPF_CFLAGS)' \
		NO_PKG_CONFIG=1 \
		EXTRA_CFLAGS='-I$(abspath $(ELF_SRC))/libelf -I$(abspath $(ZLIB_DIR))/include' \
		LDFLAGS='-L$(abspath $(ZLIB_DIR))/lib -L$(abspath $(ELF_DIR))/lib -Wl,--strip-all'
	cp "$$(ls $(SRC_DIR)/src/libbpf.so.1.* | head -n 1)" $@

clean:
	rm -rf $(BUILD_DIR) $(LIBSO)
