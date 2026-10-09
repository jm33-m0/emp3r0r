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
ARG DONUT_VERSION=1.1
ARG DONUT_SHA256=033132caee328c6d53cf6074719bfa326d88044484cc8bcbce0eaeeb73dd6494
ARG CRYSTALPALACE_SHA256=bfeb0d8fa01bf7f81845758a12300d19a4915540e7008e320ccb43b332ea6917

# Build-time/runtime dependencies, installed in a single layer with the yum
# metadata/cache removed in the same layer. `tsflags=nodocs` keeps unnecessary
# documentation out of the image.
#
# NOTE: `yum update` is intentionally omitted. It upgrades the whole base OS,
# is slow/non-reproducible, and does not change the self-contained toolchains
# installed below.
RUN yum install -y epel-release \
  && yum install -y --setopt=tsflags=nodocs \
    aria2 \
    bzip2 \
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
# Fetched with aria2 over many parallel connections: the single-stream zig
# download is slow and frequently stalls. The digest is still verified before
# anything is extracted.
RUN aria2c -x 16 -s 16 -k 1M \
      --max-tries=3 --retry-wait=3 --file-allocation=none \
      --console-log-level=warn --summary-interval=0 \
      --dir=/tmp --out=zig.tar.xz \
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

# Windows payload tooling, cached in the image so build.py copies it instead of
# downloading on every build/install run. The Crystal Palace URL is the moving
# "latest" alias, so its digest is what actually pins the release; bump it here
# when upstream cuts a new one. Digests are verified before anything is
# extracted.
RUN curl -fsSL --retry 3 -o /tmp/donut.tar.gz \
      "https://github.com/TheWover/donut/releases/download/v${DONUT_VERSION}/donut_v${DONUT_VERSION}.tar.gz" \
  && echo "${DONUT_SHA256}  /tmp/donut.tar.gz" | sha256sum -c - \
  && mkdir -p /opt/donut \
  && tar -xzf /tmp/donut.tar.gz -C /opt/donut --strip-components=1 --no-same-owner \
  && rm -f /tmp/donut.tar.gz \
  && ln -sf /opt/donut/donut /usr/local/bin/donut \
  && curl -fsSL --retry 3 -o /tmp/cpdist.tgz \
      "https://tradecraftgarden.org/download/cpdist-latest.tgz" \
  && echo "${CRYSTALPALACE_SHA256}  /tmp/cpdist.tgz" | sha256sum -c - \
  && mkdir -p /opt/crystalpalace \
  && tar -xzf /tmp/cpdist.tgz -C /opt/crystalpalace --strip-components=1 --no-same-owner \
  && rm -f /tmp/cpdist.tgz

# Set default working directory inside the container.
WORKDIR /src
