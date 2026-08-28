FROM quay.io/pypa/manylinux2014_x86_64

# Avoid interactive prompts during yum installations
ENV DEBIAN_FRONTEND=noninteractive

# Install build-time and runtime dependencies
RUN yum update -y && yum install -y epel-release \
  && yum install -y sudo curl wget git jq tmux zstd libcap make clang xz nasm ca-certificates \
  && yum clean all \
  && rm -rf /var/cache/yum \
  && ln -sf /usr/local/bin/python3.12 /usr/local/bin/python3

# Install Zig toolchain
RUN wget -q https://ziglang.org/download/0.13.0/zig-linux-x86_64-0.13.0.tar.xz \
  && tar -xpf zig-linux-x86_64-0.13.0.tar.xz -C /usr/local \
  && ln -sf /usr/local/zig-linux-x86_64-0.13.0/zig /usr/local/bin/zig \
  && rm -f zig-linux-x86_64-0.13.0.tar.xz

# Install Go toolchain
RUN wget -q https://go.dev/dl/go1.26.2.linux-amd64.tar.gz \
  && tar -C /usr/local -xzf go1.26.2.linux-amd64.tar.gz \
  && rm -f go1.26.2.linux-amd64.tar.gz

# Create zig wrappers for mingw commands
RUN echo '#!/bin/sh' > /usr/local/bin/x86_64-w64-mingw32-gcc \
  && echo 'exec zig cc -target x86_64-windows-gnu "$@"' >> /usr/local/bin/x86_64-w64-mingw32-gcc \
  && chmod +x /usr/local/bin/x86_64-w64-mingw32-gcc \
  && echo '#!/bin/sh' > /usr/local/bin/i686-w64-mingw32-gcc \
  && echo 'exec zig cc -target x86-windows-gnu "$@"' >> /usr/local/bin/i686-w64-mingw32-gcc \
  && chmod +x /usr/local/bin/i686-w64-mingw32-gcc \
  && echo '#!/bin/sh' > /usr/local/bin/x86_64-w64-mingw32-clang \
  && echo 'exec zig cc -target x86_64-windows-gnu "$@"' >> /usr/local/bin/x86_64-w64-mingw32-clang \
  && chmod +x /usr/local/bin/x86_64-w64-mingw32-clang \
  && echo '#!/bin/sh' > /usr/local/bin/x86_64-w64-mingw32-strip \
  && echo 'exit 0' >> /usr/local/bin/x86_64-w64-mingw32-strip \
  && chmod +x /usr/local/bin/x86_64-w64-mingw32-strip \
  && echo '#!/bin/sh' > /usr/local/bin/i686-w64-mingw32-strip \
  && echo 'exit 0' >> /usr/local/bin/i686-w64-mingw32-strip \
  && chmod +x /usr/local/bin/i686-w64-mingw32-strip

ENV PATH="/usr/local/go/bin:${PATH}"

# Install garble obfuscator globally
RUN go install mvdan.cc/garble@v0.17.0 \
  && mv /root/go/bin/garble /usr/local/bin/garble \
  && rm -rf /root/go

# Set default working directory inside the container
WORKDIR /src
