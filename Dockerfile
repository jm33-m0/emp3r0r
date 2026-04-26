# Stage 1: Build Environment
# Using the Go 1.26.2 image which features the Green Tea GC and improved cgo
FROM golang:1.26.2 AS builder

ENV DEBIAN_FRONTEND=noninteractive

# Install build dependencies required by build.sh
# We include sudo as the script utilizes it for system-wide installation tasks
RUN apt-get update && apt-get install -y \
  sudo \
  curl \
  git \
  jq \
  libcap2-bin \
  zstd \
  xz-utils \
  build-essential \
  tmux \
  && rm -rf /var/lib/apt/lists/*

# Set the working directory for the source code
WORKDIR /src

# Copy your local project files into the container
# This includes the core/ directory and the build scripts
COPY . .

# Change to the core directory and execute the build script
# The script handles internal dependencies like zig and sets file capabilities
WORKDIR /src/core
RUN ./build.sh --install

# Stage 2: Hardened Runtime
# A minimal Debian base to reduce the attack surface
FROM debian:trixie-slim

ENV DEBIAN_FRONTEND=noninteractive

# Metadata for versioning and security auditing
LABEL org.opencontainers.image.security.rootless="true" \
  org.opencontainers.image.description="emp3r0r server built from local source"

# Install essential runtime utilities only
# libcap2-bin is crucial for the kernel to respect internal file capabilities
RUN apt-get update && apt-get install -y \
  zstd \
  libcap2-bin \
  tmux \
  bash \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /

# Copy the portable operator bundle from the builder stage
# The bundle is located in the core directory where build.sh was executed
COPY --from=builder /src/core/emp3r0r-operator-kit.tar.zst /tmp/

# Extract the bundle to populate /usr/local/bin and /usr/local/lib/emp3r0r
RUN tar --zstd -xpf /tmp/emp3r0r-operator-kit.tar.zst -C / && \
  rm /tmp/emp3r0r-operator-kit.tar.zst

# Prepare the environment for Wireguard
RUN mkdir -p /var/run/wireguard && chmod 700 /var/run/wireguard

# Run emp3r0r with user-defined flags 
ENTRYPOINT ["emp3r0r"]
CMD ["server"]
