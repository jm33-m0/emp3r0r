FROM golang:1.26.2

# Avoid interactive prompts during apt installations
ENV DEBIAN_FRONTEND=noninteractive

# Install build-time and runtime dependencies
RUN apt-get update -qq && apt-get install -y --no-install-recommends \
  sudo curl wget git jq tmux zstd libcap2-bin build-essential ca-certificates \
  make clang mingw-w64 xz-utils \
  && rm -rf /var/lib/apt/lists/*

# Install Zig toolchain
RUN wget -q https://ziglang.org/download/0.13.0/zig-linux-x86_64-0.13.0.tar.xz \
  && tar -xpf zig-linux-x86_64-0.13.0.tar.xz -C /usr/local \
  && ln -sf /usr/local/zig-linux-x86_64-0.13.0/zig /usr/local/bin/zig \
  && rm -f zig-linux-x86_64-0.13.0.tar.xz

# Set default working directory inside the container
WORKDIR /src
