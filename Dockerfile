# Builder image for emp3r0r.
#
# Based on manylinux2014 (CentOS 7 / glibc 2.17) so the bundled cross
# toolchains produce binaries that still run on old Linux targets.
FROM quay.io/pypa/manylinux2014_x86_64

# Pinned tool versions with their SHA-256 digests. Every remote artifact is
# verified before extraction so a compromised mirror/CDN cannot inject code
# into the builder image.
ARG ZIG_VERSION=0.16.0
ARG ZIG_SHA256=70e49664a74374b48b51e6f3fdfbf437f6395d42509050588bd49abe52ba3d00
ARG GO_VERSION=1.26.2
ARG GO_SHA256=990e6b4bbba816dc3ee129eaeaf4b42f17c2800b88a2166c265ac1a200262282
ARG GARBLE_VERSION=v0.17.0

# Build-time/runtime dependencies, installed in a single layer with the yum
# metadata/cache removed in the same layer. `tsflags=nodocs` keeps unnecessary
# documentation out of the image.
#
# NOTE: `yum update` is intentionally omitted. It upgrades the whole base OS,
# is slow/non-reproducible, and does not change the self-contained toolchains
# installed below.
RUN yum install -y epel-release \
  && yum install -y --setopt=tsflags=nodocs \
    ca-certificates \
    clang \
    curl \
    git \
    jq \
    libcap \
    make \
    nasm \
    sudo \
    tmux \
    wget \
    xz \
    zstd \
  && yum clean all \
  && ln -sf /usr/local/bin/python3.12 /usr/local/bin/python3

# Zig toolchain (static build, so it runs on the glibc 2.17 base image).
RUN curl -fsSL --retry 3 -o /tmp/zig.tar.xz \
      "https://ziglang.org/download/${ZIG_VERSION}/zig-x86_64-linux-${ZIG_VERSION}.tar.xz" \
  && echo "${ZIG_SHA256}  /tmp/zig.tar.xz" | sha256sum -c - \
  && mkdir -p /opt/zig \
  && tar -xJf /tmp/zig.tar.xz -C /opt/zig --strip-components=1 --no-same-owner \
  && rm -f /tmp/zig.tar.xz \
  && ln -sf /opt/zig/zig /usr/local/bin/zig

# Go toolchain, verified against GO_SHA256. Garble is installed in the same
# layer so the module/build caches fetched for it are not left behind.
#
# `go install pkg@version` verifies the module against the Go checksum
# database (sum.golang.org) before building, so garble is integrity-checked
# as well.
ENV PATH="/usr/local/go/bin:${PATH}"
RUN curl -fsSL --retry 3 -o /tmp/go.tar.gz \
      "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz" \
  && echo "${GO_SHA256}  /tmp/go.tar.gz" | sha256sum -c - \
  && tar -C /usr/local -xzf /tmp/go.tar.gz \
  && rm -f /tmp/go.tar.gz \
  && GOBIN=/usr/local/bin go install "mvdan.cc/garble@${GARBLE_VERSION}" \
  && rm -rf /root/go /root/.cache/go-build

# mingw-w64 shims backed by `zig cc`, so code that expects the mingw
# toolchain (including CGO cross builds) transparently uses Zig.
RUN set -eux; \
    for pair in \
      "x86_64-w64-mingw32:x86_64-windows-gnu" \
      "i686-w64-mingw32:x86-windows-gnu"; do \
      prefix="${pair%%:*}"; \
      target="${pair##*:}"; \
      printf '#!/bin/sh\nexec zig cc -target %s "$@"\n' "$target" > "/usr/local/bin/${prefix}-gcc"; \
      printf '#!/bin/sh\nexit 0\n' > "/usr/local/bin/${prefix}-strip"; \
      chmod +x "/usr/local/bin/${prefix}-gcc" "/usr/local/bin/${prefix}-strip"; \
    done; \
    printf '#!/bin/sh\nexec zig cc -target x86_64-windows-gnu "$@"\n' > /usr/local/bin/x86_64-w64-mingw32-clang; \
    chmod +x /usr/local/bin/x86_64-w64-mingw32-clang

# Set default working directory inside the container.
WORKDIR /src
