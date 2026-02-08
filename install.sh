#!/bin/bash

# emp3r0r Installation Script (Source-based)
# This script installs emp3r0r by building it from source.

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
  local min_go_version="1.25.0"
  local target_go_version="1.25.0"
  local go_tarball="go${target_go_version}.linux-amd64.tar.gz"
  local go_url="https://go.dev/dl/${go_tarball}"

  if command -v go >/dev/null 2>&1; then
    local current_ver=$(go version | awk '{print $3}' | sed 's/go//')
    # Compare versions: if current >= min, we are good
    if [[ "$(printf '%s\n%s' "$min_go_version" "$current_ver" | sort -V | head -n1)" == "$min_go_version" ]]; then
      info "Go $current_ver is already installed (minimum required: $min_go_version)"
      return
    fi
    warn "Current Go version is $current_ver, but we need at least $min_go_version. Installing $target_go_version..."
  fi

  info "Downloading Go $go_version from $go_url..."
  curl -LO "$go_url" || error "Failed to download Go"
  sudo rm -rf /usr/local/go && sudo tar -C /usr/local -xzf "$go_tarball" || error "Failed to extract Go"
  rm "$go_tarball"

  # Update PATH for current session
  export PATH=$PATH:/usr/local/go/bin
  if ! grep -q "/usr/local/go/bin" ~/.bashrc; then
    echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
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

# 3. Download source
info "Checking for latest release..."
tag=$(curl -sSL https://api.github.com/repos/jm33-m0/emp3r0r/releases/latest | jq -r .tag_name)
if [[ -z "$tag" || "$tag" == "null" ]]; then
  warn "Failed to fetch latest release tag, falling back to v3"
  tag="v3"
fi
info "Downloading source tarball for $tag..."
source_url="https://github.com/jm33-m0/emp3r0r/archive/refs/tags/${tag}.tar.gz"
# if it's a branch like v3, the URL is different
if [[ "$tag" == "v3" ]]; then
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
./build.sh --install || error "Build and installation failed"

info "emp3r0r installed successfully!"
