FROM debian:trixie-slim

ENV DEBIAN_FRONTEND=noninteractive

# Metadata
LABEL org.opencontainers.image.security.rootless="true" \
  org.opencontainers.image.description="Hardened emp3r0r server"

# Install runtime dependencies for the C2 server
RUN apt-get update && apt-get install -y \
  zstd \
  libcap2-bin \
  tmux \
  bash \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /

# Copy pre-built archive
COPY core/emp3r0r-operator-kit.tar.zst /tmp/

# Extract the bundle and then DELETE it to keep the image slim
RUN tar --zstd -xpf /tmp/emp3r0r-operator-kit.tar.zst -C / && \
  rm /tmp/emp3r0r-operator-kit.tar.zst

# Prepare Wireguard environment as required by your scripts
RUN mkdir -p /var/run/wireguard && chmod 700 /var/run/wireguard

ENTRYPOINT ["emp3r0r"]
CMD ["server"]
