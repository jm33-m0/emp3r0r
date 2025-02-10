#!/bin/bash

# Function to print informational messages
info() {
  echo -e "\033[32m$1\033[0m"
}

# Function to print error messages and exit
error() {
  echo -e "\033[31m$1\033[0m"
  cd - || echo "Failed to cd back"
  exit 1
}

# Function to print warning messages
warn() {
  echo -e "\033[33m$1\033[0m"
}

# Function to check if a command exists
check_command() {
  command -v apt >/dev/null || error "This script is only for Kali/Ubuntu/Debian"
  (
    command -v "$1" >/dev/null || {
      sudo apt update && sudo apt install -y "$1"
    }
  ) || error "Failed to install $1"
}

# Function to download a file
download_file() {
  local url=$1
  local output=$2
  curl -LO "$url" || error "Failed to download $output"
}

# Function to verify the checksum of a file
verify_checksum() {
  local file=$1
  local checksum_file=$2
  local expected_checksum
  expected_checksum=$(cat "$checksum_file")
  local actual_checksum
  actual_checksum=$(sha256sum "$file" | awk '{ print $1 }')

  if [ "$expected_checksum" != "$actual_checksum" ]; then
    error "SHA256 verification failed"
  fi
}

# Check if required commands are available
check_command curl
check_command jq
check_command tmux

# Get the latest version tag from GitHub API
ver=$(curl -sSL https://api.github.com/repos/jm33-m0/emp3r0r/releases/latest | jq -r .tag_name)
warn "Downloading emp3r0r $ver"

# Get the download URLs for the tarball and sha256 file
tarball_url=$(curl -sSL https://api.github.com/repos/jm33-m0/emp3r0r/releases/latest | jq -r '.assets[] | select(.name | endswith(".tar.zst")) | .browser_download_url')
sha256_url=$(curl -sSL https://api.github.com/repos/jm33-m0/emp3r0r/releases/latest | jq -r '.assets[] | select(.name | endswith(".tar.zst.sha256")) | .browser_download_url')

# Define the filenames for the downloaded files
sha256_file="$(basename "$sha256_url")"
tarball_file="$(basename "$tarball_url")"

# Download the sha256 file
download_file "$sha256_url" "$sha256_file"
# Download the tarball if it doesn't already exist
[ -f "$tarball_file" ] || download_file "$tarball_url" "$tarball_file"

# Verify the checksum of the downloaded tarball
info "Verifying download"
verify_checksum "$tarball_file" "$sha256_file"

warn "Download and verification successful"

# Extract the tarball to /tmp/ directory
tar -xvf "$tarball_file" -C /tmp/ || error "Failed to extract tarball"
cd /tmp/emp3r0r-build || error "Failed to cd to /tmp/emp3r0r-build"

# Install emp3r0r
warn "Installing emp3r0r"
sudo ./emp3r0r --install || error "Failed to install emp3r0r"

info "emp3r0r installed successfully"
cd - || error "Failed to cd back"
