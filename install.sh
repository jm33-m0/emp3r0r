#!/bin/bash

# emp3r0r Installation Script (Source-based)
# This script installs emp3r0r by building it from source.

required_go_version="1.26.2"

# Function to print informational messages
info() {
  echo -e "\033[32m[INFO] $1\033[0m"
}

# Function to print error messages and exit
error() {
  echo -e "\033[31m[ERROR] $1\033[0m"
  exit 1
}

# Function to print warning messages
warn() {
  echo -e "\033[33m[WARN] $1\033[0m"
}

# Function to check and install basic packages via apt
check_apt_pkg() {
  if ! command -v "$1" >/dev/null 2>&1; then
    info "Installing $1 via apt..."
    sudo apt update && sudo apt install -y "$1" || error "Failed to install $1"
  fi
}

# Install Go from go.dev
install_go() {
  local target_go_version="$required_go_version"
  local go_tarball="go${target_go_version}.linux-amd64.tar.gz"
  local go_url="https://golang.org/dl/${go_tarball}"

  if command -v go >/dev/null 2>&1; then
    local current_ver
    current_ver=$(go version | awk '{print $3}' | sed 's/go//')
    if [[ "$current_ver" == "$target_go_version" ]]; then
      info "Go $current_ver is already installed"
      return
    fi
    warn "Current Go version is $current_ver, required is $target_go_version. Reinstalling..."
  fi

  info "Downloading Go $target_go_version from $go_url..."
  info "Installing with the official archive method from golang.org"
  curl -LO "$go_url" || error "Failed to download Go"
  sudo rm -rf /usr/local/go && sudo tar -C /usr/local -xzf "$go_tarball" || error "Failed to extract Go"
  rm "$go_tarball"

  # Update Go environment for current session
  export GOROOT="/usr/local/go"
  export PATH="$GOROOT/bin:$PATH"
  export GOTOOLCHAIN=local

  if ! grep -q "/usr/local/go/bin" ~/.bashrc; then
    echo 'export PATH=$PATH:/usr/local/go/bin' >>~/.bashrc
    info "Added /usr/local/go/bin to ~/.bashrc"
  fi
}

# Main installation flow
info "Starting emp3r0r installation from source"

# 0. Setup temporary workdir
workdir=$(mktemp -d)
trap 'rm -rf "$workdir"' EXIT
info "Workdir: $workdir"
cd "$workdir" || error "Failed to enter workdir"

# 1. Install basic dependencies
check_apt_pkg curl
check_apt_pkg git
check_apt_pkg tmux
# Check for build-essential by looking for make
if ! command -v make >/dev/null 2>&1; then
  check_apt_pkg build-essential
fi
# Check for libcap2-bin by looking for setcap
if ! command -v setcap >/dev/null 2>&1; then
  check_apt_pkg libcap2-bin
fi
check_apt_pkg jq

# 2. Install Go
install_go

# Explicitly use the required official Go environment when building.
export GOROOT="/usr/local/go"
export PATH="$GOROOT/bin:$PATH"
export GOTOOLCHAIN=local
[[ -x "$GOROOT/bin/go" ]] || error "Go not found at $GOROOT/bin/go"
current_ver="$($GOROOT/bin/go version | awk '{print $3}' | sed 's/^go//')"
[[ "$current_ver" == "$required_go_version" ]] || error "Go $required_go_version is required, found $current_ver"
info "Using Go toolchain: $($GOROOT/bin/go version)"

# 3. Download source
info "Checking for latest release..."
tag=$(curl -sSL https://api.github.com/repos/jm33-m0/emp3r0r/releases/latest | jq -r .tag_name)
if [[ -z "$tag" || "$tag" == "null" ]]; then
  warn "Failed to fetch latest release tag, falling back to v4"
  tag="v4"
fi
info "Downloading source tarball for $tag..."
source_url="https://github.com/jm33-m0/emp3r0r/archive/refs/tags/${tag}.tar.gz"
# if it's a branch like v4, the URL is different
if [[ "$tag" == "v4" ]]; then
  source_url="https://github.com/jm33-m0/emp3r0r/archive/refs/heads/${tag}.tar.gz"
fi
curl -L "$source_url" -o emp3r0r-src.tar.gz || error "Failed to download source"

# 4. Extract
info "Extracting source..."
mkdir emp3r0r-source
tar -xzf emp3r0r-src.tar.gz -C emp3r0r-source --strip-components=1 || error "Failed to extract source"
cd emp3r0r-source/core || error "Failed to enter core directory"

# 5. Build and Install
warn "Building and installing emp3r0r $tag (this may take a while)..."
# build.sh will handle zig and other internal dependencies
export TAG="$tag"
GOROOT="$GOROOT" PATH="$PATH" GOTOOLCHAIN="$GOTOOLCHAIN" sudo ./build.sh --install || error "Build and installation failed"

info "emp3r0r installed successfully!"
