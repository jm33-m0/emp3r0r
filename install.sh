#!/bin/bash
# emp3r0r Installation Script
# ----------------------------
# Uses Docker (or Podman) as a throwaway build container to compile emp3r0r
# from the LOCAL source tree, then installs the resulting binaries directly
# on the local machine. No Go toolchain or Zig installation required on the host.
#
# Run from the root of the emp3r0r repository:
#   ./install.sh [OPTIONS]
#
# Options:
#   --debug           Build with debug symbols (no garble obfuscation)
#   --disable-garble  Release build without garble obfuscation
#   --prefix PATH     Install prefix (default: /usr/local)
#   --skip-build      Skip Docker build; reinstall from the last cached build
#                     (requires a previous successful ./install.sh run)
#   --help            Show this help

set -euo pipefail

# ---------------------------------------------------------------------------
# Colour helpers
# ---------------------------------------------------------------------------
success() { printf "\n\e[32m[SUCCESS] %s\e[0m\n\n" "$1"; }
info() { printf "\e[34m[INFO] %s\e[0m\n" "$1"; }
error() {
  printf "\n\e[31m[ERROR] %s\e[0m\n\n" "$1" >&2
  exit 1
}
warn() { printf "\e[33m[WARN] %s\e[0m\n" "$1"; }

# ---------------------------------------------------------------------------
# Defaults / argument parsing
# ---------------------------------------------------------------------------
BUILD_ARG="--install" # passed to build.sh inside the container
PREFIX="/usr/local"
SKIP_BUILD=0
CONTAINER_ENGINE=""

# Persistent cache: the operator kit contains all compiled binaries and is used for installation
# Resolve the repo root: the directory containing this script
REPO_ROOT="$(
  cd "$(dirname "$(realpath "$0")")"
  pwd
)"
CACHED_KIT="$REPO_ROOT/core/emp3r0r-operator-kit.tar.zst"

usage() {
  grep '^#' "$0" | sed 's/^# \{0,1\}//'
  exit 0
}

while [[ $# -gt 0 ]]; do
  case "$1" in
  --debug)
    BUILD_ARG="--debug"
    shift
    ;;
  --disable-garble)
    export EMP3R0R_DISABLE_GARBLE=1
    shift
    ;;
  --prefix)
    PREFIX="$2"
    shift 2
    ;;
  --skip-build)
    SKIP_BUILD=1
    shift
    ;;
  --help | -h) usage ;;
  *) error "Unknown option: $1" ;;
  esac
done

# ---------------------------------------------------------------------------
# Detect container engine (Docker or Podman)
# ---------------------------------------------------------------------------
detect_container_engine() {
  if command -v docker >/dev/null 2>&1; then
    CONTAINER_ENGINE="docker"
  elif command -v podman >/dev/null 2>&1; then
    CONTAINER_ENGINE="podman"
  else
    warn "Neither 'docker' nor 'podman' was found. Attempting to install 'podman' via apt..."
    if command -v apt-get >/dev/null 2>&1; then
      sudo apt-get update -qq && sudo apt-get install -y podman || error "Failed to install podman"
      CONTAINER_ENGINE="podman"
    else
      error "Neither 'docker' nor 'podman' was found, and apt-get is not available to install podman. Please install docker or podman manually."
    fi
  fi
  info "Using container engine: $CONTAINER_ENGINE"
}

# ---------------------------------------------------------------------------
# Check that required host tools are available
# ---------------------------------------------------------------------------
check_host_deps() {
  local missing=()
  for dep in tar; do
    command -v "$dep" >/dev/null 2>&1 || missing+=("$dep")
  done
  if [[ ${#missing[@]} -gt 0 ]]; then
    warn "Missing host tools: ${missing[*]}. Installing via apt..."
    sudo apt-get update -qq && sudo apt-get install -y "${missing[@]}" ||
      error "Failed to install: ${missing[*]}"
  fi

  # Verify we are inside the emp3r0r repo
  [[ -f "$REPO_ROOT/core/build.sh" ]] ||
    error "core/build.sh not found under $REPO_ROOT. Run install.sh from the emp3r0r repo root."
}

# ---------------------------------------------------------------------------
# Docker build: compile emp3r0r inside a throwaway container using the LOCAL
# source tree.
# ---------------------------------------------------------------------------
docker_build() {
  info "Using local source: $REPO_ROOT"

  # Build env args
  local build_env_args=()
  [[ "${EMP3R0R_DISABLE_GARBLE:-0}" == "1" ]] &&
    build_env_args+=(-e EMP3R0R_DISABLE_GARBLE=1)
  build_env_args+=(-e EMP3R0R_BUILD_ARG="$BUILD_ARG")

  info "Starting Docker build container (golang:1.26.2)..."
  info "This may take a while on first run (Go modules + garble cache)."

  # Mounts:
  #   /src  ← local repo root (read-write; build.sh writes the operator kit here)

  local go_image="golang:1.26.2"
  local container_cmd
  container_cmd=$(
    cat <<'CONTAINER_CMD'
set -euo pipefail

# Install build-time and runtime dependencies
apt-get update -qq && apt-get install -y --no-install-recommends \
  sudo curl wget git jq tmux zstd libcap2-bin build-essential ca-certificates \
  >/dev/null

# Build from the locally mounted source tree
export PREFIX=/usr/local
export GOPATH=/root/go
cd /src/core
bash build.sh "${EMP3R0R_BUILD_ARG:---install}"

echo "Build complete."
CONTAINER_CMD
  )

  "$CONTAINER_ENGINE" run --rm \
    -v "${REPO_ROOT}:/src" \
    "${build_env_args[@]}" \
    "$go_image" \
    /bin/bash -c "$container_cmd" ||
    error "Docker build failed"

  success "Docker build completed"
}

# ---------------------------------------------------------------------------
# Extract the operator kit and execute its installer to perform local setup
# ---------------------------------------------------------------------------
install_from_operator_kit() {
  [[ -f "$CACHED_KIT" ]] || error "Operator kit not found: $CACHED_KIT"

  local tmp
  tmp="$(mktemp -d -t emp3r0r-kit-extract-XXXXXX)"

  info "Extracting operator kit to install..."
  if ! tar --zstd -xpf "$CACHED_KIT" -C "$tmp"; then
    rm -rf "$tmp"
    error "Failed to extract operator kit"
  fi

  info "Running operator kit installer..."
  if ! PREFIX="$PREFIX" bash "$tmp/emp3r0r-operator-kit/install.sh"; then
    rm -rf "$tmp"
    exit 1
  fi

  rm -rf "$tmp"
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
main() {
  if [[ "$SKIP_BUILD" -eq 1 ]]; then
    # --skip-build: reinstall from the cached operator kit without running Docker
    [[ -f "$CACHED_KIT" ]] ||
      error "No cached operator kit found at $CACHED_KIT. Run ./install.sh first to build."
    info "--skip-build: skipping Docker build, using cached operator kit"
    info "  Kit    : $CACHED_KIT"
    info "  Prefix : $PREFIX"
    info "  Cached : $(date -r "$CACHED_KIT" '+%Y-%m-%d %H:%M:%S' 2>/dev/null || stat -c '%y' "$CACHED_KIT" 2>/dev/null || echo 'unknown')"
    check_host_deps
    install_from_operator_kit
  else
    detect_container_engine
    check_host_deps
    info "Starting emp3r0r installation (Docker-based build from local source)"
    info "  Repo   : $REPO_ROOT"
    info "  Prefix : $PREFIX"
    info "  Build  : $BUILD_ARG"
    docker_build
    install_from_operator_kit
  fi

  success "emp3r0r installed successfully to $PREFIX"
  info "Run 'emp3r0r server --help' to get started."
  info "Operator kit → $REPO_ROOT/core/emp3r0r-operator-kit.tar.zst"
  info "  Transfer it to your operator machine and run: ./emp3r0r-operator-kit/install.sh"
}

main "$@"
