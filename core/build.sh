#!/bin/bash

success() {
  printf "\n\e[32m[SUCCESS] %s\e[0m\n\n" "$1"
}

info() {
  printf "\e[34m[INFO] %s\e[0m\n" "$1"
}

error() {
  printf "\n\e[31m[ERROR] %s\e[0m\n\n" "$1"
  exit 1
}

warn() {
  printf "\e[33m[WARN] %s\e[0m\n" "$1"
}

pwd="$(pwd)"
prefix="/usr/local"
[[ -n "$PREFIX" ]] && prefix="$PREFIX"
bin_dir="$prefix/bin"
data_dir="$prefix/lib/emp3r0r"
build_dir="$data_dir/build"
required_go_version="1.26.2"
required_free_kb=$((10 * 1024 * 1024))
# Set EMP3R0R_DISABLE_GARBLE=1 to use plain go build for non-debug builds.
disable_garble="${EMP3R0R_DISABLE_GARBLE:-0}"
operator_bundle_name="emp3r0r-operator-kit.tar.zst"

# build and tar
temp=$(mktemp -d -t emp3r0r-build-XXXXXXXXXX) || error "Failed to create temporary directory"
[[ -d "$temp" ]] || mkdir -p "$temp"
magic_str="$(head -c 32 </dev/urandom | sha256sum | awk '{print $1}')"
magic_str="$(head -c 32 </dev/urandom | sha256sum | awk '{print $1}')"

# GOPATH
[[ -z "$GOPATH" ]] && export GOPATH="$HOME/go"
export PATH="$GOPATH/bin:$PATH"

check_required_go() {
  local go_bin
  go_bin="$(command -v go 2>/dev/null)"
  [[ -n "$go_bin" ]] || error "You need to set up Go $required_go_version first"

  local current_go_version
  current_go_version="$($go_bin version | awk '{print $3}' | sed 's/^go//')"
  if [[ "$current_go_version" != "$required_go_version" ]]; then
    error "Go $required_go_version is required, found $current_go_version"
  fi

  # Use the official Go installation environment explicitly during builds.
  export GOROOT="/usr/local/go"
  export PATH="$GOROOT/bin:$GOPATH/bin:$PATH"
  export GOTOOLCHAIN=local

  GO_BIN="$GOROOT/bin/go"
  [[ -x "$GO_BIN" ]] || GO_BIN="$go_bin"
  info "Using Go toolchain: $($GO_BIN version)"
}

check_disk_space() {
  local path
  for path in "$pwd" "/"; do
    local avail_kb
    avail_kb="$(df -Pk "$path" | awk 'NR==2 {print $4}')"
    [[ -n "$avail_kb" ]] || error "Failed to check available disk space for $path"

    if ((avail_kb < required_free_kb)); then
      local avail_gb
      avail_gb="$(awk -v kb="$avail_kb" 'BEGIN {printf "%.2f", kb/1024/1024}')"
      warn "$path only has ${avail_gb}GB available. Installation might fail due to garble's huge cache"
    fi
  done

  info "Disk space check passed: at least 10GB free for build and temp files"
}

check_zig() {
  if ! command -v zig >/dev/null 2>&1; then
    error "zig not found. Please run build inside the builder container, or install zig 0.13.0 manually on the host."
  else
    info "zig is already installed"
  fi
}

find_installed_prefix() {
  local detected_prefix="$prefix"
  if [[ ! -x "$detected_prefix/lib/emp3r0r/emp3r0r-cc" ]]; then
    for candidate in "/usr/local" "/usr"; do
      if [[ -x "$candidate/lib/emp3r0r/emp3r0r-cc" ]]; then
        detected_prefix="$candidate"
        break
      fi
    done
  fi

  [[ -x "$detected_prefix/lib/emp3r0r/emp3r0r-cc" ]] || error "emp3r0r is not installed. Please run --install on the C2 server first"
  echo "$detected_prefix"
}

DONUT_URL="https://github.com/TheWover/donut/releases/download/v1.1/donut_v1.1.tar.gz"
DONUT_ARCHIVE_NAME="donut_v1.1.tar.gz"

download_file() {
  local url="$1"
  local dest="$2"
  if command -v curl >/dev/null 2>&1; then
    curl -sSL --connect-timeout 15 "$url" -o "$dest" 2>/dev/null
  elif command -v wget >/dev/null 2>&1; then
    wget -qO "$dest" "$url" 2>/dev/null
  else
    return 1
  fi
}

install_donut() {
  local target_dir="$1"
  local search_dir="${2:-}"
  local donut_archive=""

  if [[ -n "$search_dir" && -f "$search_dir/$DONUT_ARCHIVE_NAME" ]]; then
    donut_archive="$search_dir/$DONUT_ARCHIVE_NAME"
  fi

  if [[ -z "$donut_archive" || ! -f "$donut_archive" ]]; then
    donut_archive="$(mktemp -t donut_v0.1.XXXXXX.tar.gz 2>/dev/null || echo "/tmp/$DONUT_ARCHIVE_NAME")"
    info "Downloading donut archive from $DONUT_URL..."
    download_file "$DONUT_URL" "$donut_archive" || warn "Failed to download $DONUT_URL"
  fi

  if [[ -f "$donut_archive" ]]; then
    info "Extracting and installing donut..."
    local donut_tmp
    donut_tmp="$(mktemp -d)"
    if tar -xzf "$donut_archive" -C "$donut_tmp" 2>/dev/null; then
      local donut_bin
      donut_bin="$(find "$donut_tmp" -type f -name "donut" | head -n 1)"
      if [[ -n "$donut_bin" && -f "$donut_bin" ]]; then
        mkdir -p "$target_dir/bin" "/usr/local/bin"
        cp -af "$donut_bin" "$target_dir/bin/donut"
        chmod 755 "$target_dir/bin/donut"
        ln -sf "$target_dir/bin/donut" "/usr/local/bin/donut"
        info "Linked donut executable to /usr/local/bin/donut"
      else
        warn "Executable 'donut' not found inside $donut_archive"
      fi
    else
      warn "Failed to extract $donut_archive"
    fi
    rm -rf "$donut_tmp"
  else
    warn "Donut archive could not be obtained; skipping donut installation"
  fi
}

package_operator_bundle() {
  local installed_prefix
  installed_prefix="$(find_installed_prefix)"
  info "Using installed files from $installed_prefix"

  # Stage the operator bundle in a temp directory so we can inject install.sh
  local bundle_stage
  bundle_stage="$(mktemp -d -t emp3r0r-operator-bundle-XXXXXX)" || error "Failed to create bundle staging dir"
  trap 'rm -rf "$bundle_stage"' RETURN

  local kit_dir="$bundle_stage/emp3r0r-operator-kit"
  mkdir -p "$kit_dir"

  # Copy binaries and data into the kit directory (preserving relative paths)
  local bin_src="$installed_prefix/bin/emp3r0r"
  local lib_src="$installed_prefix/lib/emp3r0r"

  mkdir -p "$kit_dir/bin" "$kit_dir/lib/emp3r0r"
  cp -aL "$bin_src" "$kit_dir/bin/emp3r0r" || error "Failed to copy emp3r0r launcher"
  cp -aL "$lib_src/emp3r0r-cc" "$kit_dir/lib/emp3r0r/emp3r0r-cc" || error "Failed to copy emp3r0r-cc"
  cp -aL "$lib_src/emp3r0r-cat" "$kit_dir/lib/emp3r0r/emp3r0r-cat" || error "Failed to copy emp3r0r-cat"
  # listener lives in bin/, include it so the kit is also usable for full reinstalls
  local listener_src="$installed_prefix/bin/emp3r0r-listener"
  if [[ -f "$listener_src" ]]; then
    cp -aL "$listener_src" "$kit_dir/bin/emp3r0r-listener" || warn "Failed to copy emp3r0r-listener"
  else
    warn "emp3r0r-listener not found at $listener_src; skipping"
  fi

  local dir
  for dir in build modules tmux; do
    if [[ -d "$lib_src/$dir" ]]; then
      cp -aR "$lib_src/$dir" "$kit_dir/lib/emp3r0r/$dir" || warn "Failed to copy $dir"
    else
      warn "$lib_src/$dir not found; operator package may be incomplete"
    fi
  done

  # Download donut tar archive from release URL to include in the kit
  info "Downloading donut package from $DONUT_URL..."
  download_file "$DONUT_URL" "$kit_dir/$DONUT_ARCHIVE_NAME" || warn "Could not download $DONUT_URL at package time"

  # Generate the self-contained install.sh that operators run after extracting the kit
  cat >"$kit_dir/install.sh" <<'OPERATOR_INSTALL_EOF'
#!/bin/bash
# emp3r0r Operator Kit Installer
# --------------------------------
# Run this script once after transferring the operator kit to your machine.
# It installs emp3r0r into /usr/local, sets required capabilities, creates
# the WireGuard runtime directory, and sets up shell completion automatically.
#
# Usage: sudo ./install.sh
#        ./install.sh          (will re-exec itself with sudo)

set -euo pipefail

DONUT_URL="https://github.com/TheWover/donut/releases/download/v1.1/donut_v1.1.tar.gz"
DONUT_ARCHIVE_NAME="donut_v1.1.tar.gz"

success() { printf "\n\e[32m[SUCCESS] %s\e[0m\n\n" "$1"; }
info()    { printf "\e[34m[INFO] %s\e[0m\n" "$1"; }
error()   { printf "\n\e[31m[ERROR] %s\e[0m\n\n" "$1"; exit 1; }
warn()    { printf "\e[33m[WARN] %s\e[0m\n" "$1"; }

download_file() {
  local url="$1"
  local dest="$2"
  if command -v curl >/dev/null 2>&1; then
    curl -sSL --connect-timeout 15 "$url" -o "$dest" 2>/dev/null
  elif command -v wget >/dev/null 2>&1; then
    wget -qO "$dest" "$url" 2>/dev/null
  else
    return 1
  fi
}

install_donut() {
  local target_dir="$1"
  local search_dir="${2:-}"
  local donut_archive=""

  if [[ -n "$search_dir" && -f "$search_dir/$DONUT_ARCHIVE_NAME" ]]; then
    donut_archive="$search_dir/$DONUT_ARCHIVE_NAME"
  fi

  if [[ -z "$donut_archive" || ! -f "$donut_archive" ]]; then
    donut_archive="$(mktemp -t donut_v0.1.XXXXXX.tar.gz 2>/dev/null || echo "/tmp/$DONUT_ARCHIVE_NAME")"
    info "Downloading donut archive from $DONUT_URL..."
    download_file "$DONUT_URL" "$donut_archive" || warn "Failed to download $DONUT_URL"
  fi

  if [[ -f "$donut_archive" ]]; then
    info "Extracting and installing donut..."
    local donut_tmp
    donut_tmp="$(mktemp -d)"
    if tar -xzf "$donut_archive" -C "$donut_tmp" 2>/dev/null; then
      local donut_bin
      donut_bin="$(find "$donut_tmp" -type f -name "donut" | head -n 1)"
      if [[ -n "$donut_bin" && -f "$donut_bin" ]]; then
        mkdir -p "$target_dir/bin" "/usr/local/bin"
        cp -af "$donut_bin" "$target_dir/bin/donut"
        chmod 755 "$target_dir/bin/donut"
        ln -sf "$target_dir/bin/donut" "/usr/local/bin/donut"
        info "Linked donut executable to /usr/local/bin/donut"
      else
        warn "Executable 'donut' not found inside $donut_archive"
      fi
    else
      warn "Failed to extract $donut_archive"
    fi
    rm -rf "$donut_tmp"
  else
    warn "Donut archive could not be obtained; skipping donut installation"
  fi
}

# Re-exec with sudo if not root
if [[ "$EUID" -ne 0 ]]; then
  info "Re-running with sudo..."
  exec sudo bash "$0" "$@"
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PREFIX="${PREFIX:-/usr/local}"
BIN_DIR="$PREFIX/bin"
DATA_DIR="$PREFIX/lib/emp3r0r"
INSTALL_USER="${SUDO_USER:-${USER:-$(id -un)}}"

info "Installing emp3r0r operator kit to $PREFIX"
info "Operator user: $INSTALL_USER"

# Verify kit contents
[[ -f "$SCRIPT_DIR/bin/emp3r0r" ]]              || error "Kit is missing: bin/emp3r0r"
[[ -f "$SCRIPT_DIR/lib/emp3r0r/emp3r0r-cc" ]]  || error "Kit is missing: lib/emp3r0r/emp3r0r-cc"
[[ -f "$SCRIPT_DIR/lib/emp3r0r/emp3r0r-cat" ]] || error "Kit is missing: lib/emp3r0r/emp3r0r-cat"

# -- Check required system dependencies --
for dep in setcap tmux; do
  if ! command -v "$dep" >/dev/null 2>&1; then
    warn "Required tool '$dep' not found. Attempting to install..."
    if command -v apt-get >/dev/null 2>&1; then
      apt-get update -qq && apt-get install -y \
        "$( [[ "$dep" == "setcap" ]] && echo libcap2-bin || echo "$dep" )" \
        || error "Failed to install $dep"
    elif command -v yum >/dev/null 2>&1; then
      yum install -y \
        "$( [[ "$dep" == "setcap" ]] && echo libcap || echo "$dep" )" \
        || error "Failed to install $dep via yum"
    else
      error "$dep is required but could not be installed automatically. Please install it manually."
    fi
  fi
done

# -- Stop any running emp3r0r session --
if command -v tmux >/dev/null 2>&1 && tmux has-session -t emp3r0r 2>/dev/null; then
  warn "Stopping existing emp3r0r tmux session..."
  tmux kill-session -t emp3r0r || true
fi

# -- Install files --
info "Creating directories..."
mkdir -p "$BIN_DIR" "$DATA_DIR/build"

info "Installing binaries and data..."
cp -afR "$SCRIPT_DIR/bin/emp3r0r"             "$BIN_DIR/emp3r0r"
if [[ -f "$SCRIPT_DIR/bin/emp3r0r-listener" ]]; then
  cp -afR "$SCRIPT_DIR/bin/emp3r0r-listener"  "$BIN_DIR/emp3r0r-listener"
  chmod 755 "$BIN_DIR/emp3r0r-listener"
fi
cp -afR "$SCRIPT_DIR/lib/emp3r0r/emp3r0r-cc"  "$DATA_DIR/emp3r0r-cc"
cp -afR "$SCRIPT_DIR/lib/emp3r0r/emp3r0r-cat" "$DATA_DIR/emp3r0r-cat"
chmod 755 "$DATA_DIR/emp3r0r-cc" "$DATA_DIR/emp3r0r-cat" "$BIN_DIR/emp3r0r"

for dir in build modules tmux; do
  if [[ -d "$SCRIPT_DIR/lib/emp3r0r/$dir" ]]; then
    cp -afR "$SCRIPT_DIR/lib/emp3r0r/$dir" "$DATA_DIR/"
    info "Installed $dir"
  fi
done

# -- Install Donut package --
install_donut "$DATA_DIR" "$SCRIPT_DIR"

# Fix tmux config path (replace placeholder with actual install path)
tmux_conf="$DATA_DIR/tmux/.tmux.conf"
if [[ -f "$tmux_conf" ]]; then
  tmux_sh_dir="$DATA_DIR/tmux/sh"
  replace="$(echo -n "$tmux_sh_dir" | sed 's/\//\\\//g')"
  sed -i "s/~\/sh/$replace/g" "$tmux_conf"
  info "Fixed tmux config paths"
fi

# -- Set capabilities for WireGuard --
info "Setting cap_net_admin on emp3r0r-cc..."
setcap cap_net_admin=eip "$DATA_DIR/emp3r0r-cc" || error "setcap failed — is libcap2-bin installed?"

# -- WireGuard runtime directory --
info "Creating /var/run/wireguard..."
mkdir -p /var/run/wireguard
chown "${INSTALL_USER}:${INSTALL_USER}" /var/run/wireguard || \
  chown "${INSTALL_USER}" /var/run/wireguard || true
chmod 0755 /var/run/wireguard

# Persist the directory across reboots via tmpfiles.d
if [[ -d "/etc/tmpfiles.d" ]]; then
  echo "d /var/run/wireguard 0755 ${INSTALL_USER} ${INSTALL_USER}" \
    >/etc/tmpfiles.d/emp3r0r-wireguard.conf
  info "Created /etc/tmpfiles.d/emp3r0r-wireguard.conf"
fi

# -- Shell completion --
CC_BIN="$DATA_DIR/emp3r0r-cc"

# Bash completion
if [[ -d "/etc/bash_completion.d" ]]; then
  "$CC_BIN" completion bash >"/etc/bash_completion.d/emp3r0r" 2>/dev/null && \
    chmod 644 "/etc/bash_completion.d/emp3r0r" && \
    info "Installed Bash completion to /etc/bash_completion.d/emp3r0r" || \
    warn "Failed to install Bash completion"
fi

# Zsh completion
ZSH_COMP_DIR=""
# Prefer the invoking user's personal completion dirs
REAL_HOME="$(eval echo "~$INSTALL_USER" 2>/dev/null || echo "/home/$INSTALL_USER")"
if [[ -d "$REAL_HOME/.zsh/completions" ]]; then
  ZSH_COMP_DIR="$REAL_HOME/.zsh/completions"
else
  for d in "/usr/local/share/zsh/site-functions" "/usr/share/zsh/site-functions" "/usr/share/zsh/vendor-completions"; do
    if [[ -d "$d" ]]; then
      ZSH_COMP_DIR="$d"
      break
    fi
  done
fi
if [[ -n "$ZSH_COMP_DIR" ]]; then
  mkdir -p "$ZSH_COMP_DIR"
  "$CC_BIN" completion zsh >"$ZSH_COMP_DIR/_emp3r0r" 2>/dev/null && \
    chmod 644 "$ZSH_COMP_DIR/_emp3r0r" && \
    info "Installed Zsh completion to $ZSH_COMP_DIR/_emp3r0r" || \
    warn "Failed to install Zsh completion"
else
  warn "No Zsh completion directory found; skipping Zsh completion install"
fi

success "emp3r0r operator kit installed successfully!"
info "Run 'emp3r0r client --help' to get started."
info "Use the connection command printed by the C2 server to connect."
OPERATOR_INSTALL_EOF

  chmod 755 "$kit_dir/install.sh"

  # Create the final archive from the staging directory
  tar -I zstd -cpf "$pwd/$operator_bundle_name" -C "$bundle_stage" "emp3r0r-operator-kit" ||
    error "failed to create operator package"

  success "Created portable operator package: $pwd/$operator_bundle_name"
  success "Transfer to your operator machine, then:"
  success "  tar -I zstd -xpf $operator_bundle_name && ./emp3r0r-operator-kit/install.sh"
}

build_agent_pure() {
  local arch=$1
  local os=$2
  local output=$3
  local extra_flags=$4
  local extra_extldflags=$5
  info "Building pure agent stub for $os $arch"

  local tags="netgo agent"
  [[ "$arg1" != "--debug" ]] && tags="netgo release agent"

  local win_gui_flag=""
  [[ "$arg1" != "--debug" ]] && [[ "$os" == "windows" ]] && win_gui_flag="-H=windowsgui "

  # Add extra extldflags if provided
  local current_ldflags="$ldflags"
  if [[ -n "$extra_extldflags" ]]; then
    current_ldflags="$current_ldflags -extldflags '$extra_extldflags'"
  fi

  # Default build command (CGO_ENABLED=0)
  local build_cmd="CGO_ENABLED=0 GOARCH=$arch GOOS=$os sh -c \"$gobuild_cmd $build_opt $extra_flags -trimpath -buildvcs=false -tags '$tags' -o \\\"$temp/$output\\\" -ldflags=\\\"${win_gui_flag}${current_ldflags}\\\"\""

  echo "Running: $build_cmd"
  {
    cd "$pwd/cmd/agent" &&
      eval "$build_cmd"
  } || error "build pure agent stub for $os $arch"
}

build_agent_cgo() {
  local arch=$1
  local os=$2
  local output=$3
  local extra_flags=$4
  local extra_extldflags=$5
  info "Building CGO agent stub for $os $arch"

  local tags="netgo agent"
  [[ "$arg1" != "--debug" ]] && tags="netgo release agent"

  # Zig + CGO + Static Linking
  local cc_cmd="zig cc -target"
  case "$arch" in
  "amd64") cc_cmd="$cc_cmd x86_64-linux-musl" ;;
  "386") cc_cmd="$cc_cmd x86-linux-musl" ;; # Zig might use i386-linux-musl
  "arm64") cc_cmd="$cc_cmd aarch64-linux-musl" ;;
  "riscv64") cc_cmd="$cc_cmd riscv64-linux-musl" ;;
  *) cc_cmd="musl-gcc" ;; # Fallback if specific arc not strictly handled or just generic
  esac

  # Zig target adjustment for 386 if needed
  if [[ "$arch" == "386" ]]; then cc_cmd="zig cc -target x86-linux-musl"; fi

  # We need to tell Go to use this CC
  # And we add external linker flags for static build
  # Also add -s to extldflags if not debugging, to ensure the binary is stripped
  local extldflags="-static -Wl,--gc-sections"
  if [[ "$extra_extldflags" == *"-static-pie"* ]]; then
    extldflags="-s -Wl,--gc-sections"
  fi
  [[ "$arg1" != "--debug" ]] && extldflags="$extldflags -s"

  # Append extra extldflags if provided
  if [[ -n "$extra_extldflags" ]]; then
    extldflags="$extldflags $extra_extldflags"
  fi

  local build_cmd="CGO_ENABLED=1 CC=\"$cc_cmd\" GOARCH=$arch GOOS=$os sh -c \"$gobuild_cmd $build_opt $extra_flags -trimpath -buildvcs=false -tags '$tags' -o \\\"$temp/$output\\\" -ldflags=\\\"$ldflags -linkmode external -extldflags '$extldflags'\\\"\""

  echo "Running: $build_cmd"
  {
    cd "$pwd/cmd/agent" &&
      eval "$build_cmd"
  } || error "build CGO agent stub for $os $arch"
}

build_shared_object() {
  local arch=$1
  local os=$2
  local output=$3
  info "Building shared object for $os $arch"

  local tags="emp3r0r_so"
  [[ "$arg1" != "--debug" ]] && tags="release emp3r0r_so"

  local build_cmd
  local extldflags="-nostdlib -nodefaultlibs -Wl,--gc-sections"
  [[ "$arg1" != "--debug" ]] && extldflags="-s $extldflags"
  local win_gui_flag=""
  [[ "$arg1" != "--debug" ]] && [[ "$os" == "windows" ]] && win_gui_flag="-H=windowsgui "
  case "$os" in
  windows)
    tags="netgo $tags"
    case "$arch" in
    386)
      build_cmd="CGO_ENABLED=1 CC=\"zig cc -target x86-windows-gnu\" CXX=\"zig c++ -target x86-windows-gnu\" GOOS=$os GOARCH=$arch $gobuild_cmd $build_opt -trimpath -buildvcs=false -tags \"$tags\" -o \"$temp/$output\" -buildmode c-shared -ldflags=\"${win_gui_flag}$ldflags -linkmode external -extldflags '$extldflags'\""
      ;;
    amd64)
      build_cmd="CGO_ENABLED=1 CC=\"zig cc -target x86_64-windows-gnu\" CXX=\"zig c++ -target x86_64-windows-gnu\" GOOS=$os GOARCH=$arch $gobuild_cmd $build_opt -trimpath -buildvcs=false -tags \"$tags\" -o \"$temp/$output\" -buildmode c-shared -ldflags=\"${win_gui_flag}$ldflags -linkmode external -extldflags '$extldflags'\""
      ;;
    arm64)
      build_cmd="CGO_ENABLED=1 CC=\"zig cc -target aarch64-windows-gnu\" CXX=\"zig c++ -target aarch64-windows-gnu\" GOOS=$os GOARCH=$arch $gobuild_cmd $build_opt -trimpath -buildvcs=false -tags \"$tags\" -o \"$temp/$output\" -buildmode c-shared -ldflags=\"${win_gui_flag}$ldflags -linkmode external -extldflags '$extldflags'\""
      ;;
    esac
    ;;
  linux)
    case "$arch" in
    386)
      build_cmd="CGO_ENABLED=1 CC=\"zig cc -target x86-linux-gnu.2.17\" GOARCH=$arch $gobuild_cmd $build_opt -trimpath -buildvcs=false -tags \"$tags\" -o \"$temp/$output\" -buildmode c-shared -ldflags=\"$ldflags -linkmode external -extldflags '$extldflags'\""
      ;;
    amd64)
      build_cmd="CGO_ENABLED=1 GOARCH=$arch $gobuild_cmd $build_opt -trimpath -buildvcs=false -tags \"$tags\" -o \"$temp/$output\" -buildmode c-shared -ldflags=\"$ldflags -linkmode external -extldflags '$extldflags'\""
      ;;
    arm)
      build_cmd="CGO_ENABLED=1 CC=\"zig cc -target arm-linux-gnueabihf.2.17\" GOARCH=$arch $gobuild_cmd $build_opt -trimpath -buildvcs=false -tags \"$tags\" -o \"$temp/$output\" -buildmode c-shared -ldflags=\"$ldflags -linkmode external -extldflags '$extldflags'\""
      ;;
    arm64)
      build_cmd="CGO_ENABLED=1 CC=\"zig cc -target aarch64-linux-gnu.2.17\" GOARCH=$arch $gobuild_cmd $build_opt -trimpath -buildvcs=false -tags \"$tags\" -o \"$temp/$output\" -buildmode c-shared -ldflags=\"$ldflags -linkmode external -extldflags '$extldflags'\""
      ;;
    riscv64)
      # the built shared object is untested
      build_cmd="CGO_ENABLED=1 CC=\"zig cc -target riscv64-linux-musl\" GOARCH=$arch $gobuild_cmd $build_opt -trimpath -buildvcs=false -tags \"$tags\" -o \"$temp/$output\" -buildmode c-shared -ldflags=\"$ldflags -linkmode external -extldflags '$extldflags'\""
      ;;
    esac
    ;;
  esac
  echo "Running: $build_cmd"
  {
    cd "$pwd/cmd/agent" &&
      eval "$build_cmd"
  } || error "build shared object for $os $arch"
}

check_build_toolchain() {
  local is_container=0
  if [[ -f /.dockerenv || -f /run/.containerenv ]]; then
    is_container=1
  fi

  local toolchains=()
  command -v make >/dev/null 2>&1 || toolchains+=("make")
  command -v clang >/dev/null 2>&1 || toolchains+=("clang")
  command -v x86_64-w64-mingw32-gcc >/dev/null 2>&1 || toolchains+=("mingw-w64")
  command -v i686-w64-mingw32-gcc >/dev/null 2>&1 || toolchains+=("mingw-w64")
  command -v gcc >/dev/null 2>&1 || toolchains+=("build-essential")

  local unique_toolchains=()
  for t in "${toolchains[@]}"; do
    if [[ " ${unique_toolchains[*]} " != *" ${t} "* ]]; then
      unique_toolchains+=("$t")
    fi
  done

  if [[ ${#unique_toolchains[@]} -gt 0 ]]; then
    error "Missing required toolchains: ${unique_toolchains[*]}. Please run build inside the builder container, or install them manually on the host."
  fi
}

build() {
  # build
  # -----
  check_build_toolchain
  check_required_go
  check_disk_space
  local mod_opt=""
  if [[ -d "vendor" && -f "vendor/modules.txt" ]]; then
    info "Using existing vendor/ directory for local modules"
    mod_opt="-mod=vendor"
  else
    info "vendor/ directory missing or incomplete, attempting to vendor dependencies..."
    if $GO_BIN mod vendor; then
      info "Successfully vendored modules"
      mod_opt="-mod=vendor"
    else
      warn "go mod vendor failed; falling back to default Go module resolution"
      mod_opt=""
    fi
  fi

  # Check for zig installation
  check_zig

  ldflags="-v -X 'github.com/jm33-m0/emp3r0r/core/internal/def.MagicString=$magic_str'"
  ldflags+=" -X 'github.com/jm33-m0/emp3r0r/core/internal/def.Version=$(get_version)'"
  if [[ "$1" = "--debug" ]]; then
    gobuild_cmd="$GO_BIN"
    build_opt="build $mod_opt"
  else
    if [[ "$disable_garble" = "1" || "$disable_garble" = "true" || "$disable_garble" = "yes" ]]; then
      gobuild_cmd="$GO_BIN"
      build_opt="build $mod_opt"
      ldflags+=" -s -w"
      info "Garble disabled by EMP3R0R_DISABLE_GARBLE=$disable_garble, using plain go build"
    else
      gobuild_cmd="garble"
      build_opt="-tiny -seed=random build $mod_opt"
      ldflags+=" -s -w"
      info "Using garble for obfuscation"
      command -v garble >/dev/null 2>&1 || error "garble not found. It should be installed in the builder container."
    fi
  fi

  info "Building CC"
  {
    cd cmd/cc && CGO_ENABLED=0 $GO_BIN build $mod_opt -o "$temp/cc.exe" -ldflags="$ldflags"
  } || error "build cc"
  info "Building cat"
  {
    cd "$pwd/cmd/cat" && CGO_ENABLED=0 $GO_BIN build $mod_opt -o "$temp/cat.exe" -ldflags="$ldflags"
  } || error "build cat"
  info "Building listener"
  {
    cd "$pwd/cmd/listener" && CGO_ENABLED=0 $GO_BIN build $mod_opt -o "$temp/listener.exe" -ldflags="$ldflags"
  } || error "build listener"

  # Add -buildid= for agent builds to further reduce binary size
  [[ "$1" != "--debug" ]] && ldflags+=" -buildid="

  # Linux
  # PIE builds for all architectures where supported
  local pie_flags="-buildmode=pie"
  local ext_pie="-static-pie"

  # Standard Linux agents (PIE)
  build_agent_cgo "amd64" "linux" "stub-amd64" "$pie_flags" "$ext_pie"
  build_agent_cgo "386" "linux" "stub-386" "$pie_flags" "$ext_pie"
  build_agent_pure "arm" "linux" "stub-arm"
  build_agent_cgo "arm64" "linux" "stub-arm64" "$pie_flags" "$ext_pie"

  # MIPS often has issues with PIE, keep static for now unless explicitly requested or tested
  build_agent_pure "mips" "linux" "stub-mips"
  build_agent_pure "mips64" "linux" "stub-mips64"

  build_agent_cgo "riscv64" "linux" "stub-riscv64" "$pie_flags" "$ext_pie"
  build_agent_pure "ppc64" "linux" "stub-ppc64"

  # Windows
  build_agent_pure "amd64" "windows" "stub-win-amd64"
  build_agent_pure "386" "windows" "stub-win-386"
  build_agent_pure "arm64" "windows" "stub-win-arm64"

  # Shared Objects
  build_shared_object "amd64" "windows" "stub-win-amd64.dll"
  build_shared_object "386" "windows" "stub-win-386.dll"
  build_shared_object "arm64" "windows" "stub-win-arm64.dll"
  build_shared_object "amd64" "linux" "stub-amd64.so"
  build_shared_object "386" "linux" "stub-386.so"
  build_shared_object "arm" "linux" "stub-arm.so"
  build_shared_object "riscv64" "linux" "stub-riscv64.so"

  # error: https://github.com/golang/go/issues/22040
  # build_shared_object "arm64" "linux" "stub-arm64.so"

  # Build modules with a make_all.sh wrapper
  info "Building complex modules with make_all.sh..."
  for mod_dir in "$pwd"/modules/*; do
    if [[ -d "$mod_dir" && -f "$mod_dir/make_all.sh" ]]; then
      info "Running make_all.sh in $(basename "$mod_dir")"
      {
        cd "$mod_dir" &&
          chmod +x make_all.sh &&
          ./make_all.sh
      } || warn "Failed to build modules in $(basename "$mod_dir") via make_all.sh"
    fi
  done

  # Build basic Linux test BOFs
  info "Building Linux test BOFs"
  if [[ -d "$pwd/modules/hello_linux" ]]; then
    make -C "$pwd/modules/hello_linux" || warn "Failed to build hello_linux module"
  fi
  if [[ -d "$pwd/modules/process_list_handles_linux" ]]; then
    make -C "$pwd/modules/process_list_handles_linux" || warn "Failed to build process_list_handles_linux module"
  fi
}

do_uninstall() {
  [[ "$EUID" -eq 0 ]] || error "You must be root to uninstall emp3r0r"
  info "emp3r0r will be uninstalled from $prefix"

  # data
  rm -rf "$build_dir" || error "Failed to remove $build_dir"
  rm -rf "$data_dir" || error "Failed to remove $data_dir"

  # emp3r0r launcher
  rm -f "$bin_dir/emp3r0r" || error "Failed to remove $bin_dir/emp3r0r"

  # Remove completion files
  info "Removing completion files"
  rm -f "/etc/bash_completion.d/emp3r0r"

  # Try to remove zsh completion from common locations
  for zsh_dir in "/usr/local/share/zsh/site-functions" "/usr/share/zsh/site-functions" "/usr/share/zsh/vendor-completions" "$HOME/.zsh/completions"; do
    if [ -f "$zsh_dir/_emp3r0r" ]; then
      rm -f "$zsh_dir/_emp3r0r"
      info "Removed Zsh completion from $zsh_dir"
    fi
  done

  # Check if ZDOTDIR is set and remove completion there if it exists
  if [ -n "$ZDOTDIR" ] && [ -f "$ZDOTDIR/completions/_emp3r0r" ]; then
    rm -f "$ZDOTDIR/completions/_emp3r0r"
    info "Removed Zsh completion from $ZDOTDIR/completions"
  fi

  success "emp3r0r has been removed"
}

do_install() {
  [[ "$EUID" -eq 0 ]] || error "You must be root to install emp3r0r"
  info "emp3r0r will be installed to $prefix"

  # check if tmux is installed
  if ! command -v tmux >/dev/null 2>&1; then
    error "tmux not found"
  fi

  # check if emp3r0r is running
  if tmux has-session -t emp3r0r 2>/dev/null; then
    tmux kill-session -t emp3r0r || error "Failed to kill emp3r0r"
  fi

  # create directories
  mkdir -p "$build_dir" || error "Failed to mkdir $build_dir"
  cp -avR "$temp"/tmux "$data_dir" || error "tmux"
  cp -avR "$temp"/modules "$data_dir" || error "modules"
  cp -avR "$temp"/stub* "$build_dir" || error "stub"

  # fix tmux config
  tmux_dir="$data_dir/tmux"
  replace=$(echo -n "$tmux_dir/sh" | sed 's/\//\\\//g')
  sed -i "s/~\/sh/$replace/g" "$tmux_dir/.tmux.conf"

  # emp3r0r binaries
  chmod 755 "$temp"/cc.exe "$temp"/cat.exe
  cp -avfR "$temp"/emp3r0r "$bin_dir/emp3r0r" || error "emp3r0r-main"
  cp -avfR "$temp"/listener.exe "$bin_dir/emp3r0r-listener" || error "emp3r0r-listener"
  cp -avfR "$temp"/cc.exe "$data_dir/emp3r0r-cc" || error "emp3r0r-cc"
  cp -avfR "$temp"/cat.exe "$data_dir/emp3r0r-cat" || error "emp3r0r-cat"

  # -- Install Donut package --
  install_donut "$data_dir" "$temp"

  # set capabilities for cc and setup wireguard runtime dir
  local is_container=0
  if [[ -f /.dockerenv || -f /run/.containerenv ]]; then
    is_container=1
  fi

  if [[ "$is_container" -eq 0 ]]; then
    setcap cap_net_admin=eip "$data_dir/emp3r0r-cc" || error "setcap"
    mkdir -p /var/run/wireguard || error "mkdir wireguard"
    chown "$(id -nu):$(id -ng)" /var/run/wireguard || error "chown wireguard"

    # tmpfiles.d entry to persist the directory
    if [[ -d "/etc/tmpfiles.d" ]]; then
      local _user="${SUDO_USER:-$USER}"
      echo "d /var/run/wireguard 0755 $_user $_user" >/etc/tmpfiles.d/emp3r0r-wireguard.conf
    fi

    # Auto-complete
    # Find a suitable zsh completion directory
    zsh_completion_dir=""
    # Check user's personal completion directory first
    if [ -n "$ZDOTDIR" ] && [ -d "$ZDOTDIR/completions" ]; then
      zsh_completion_dir="$ZDOTDIR/completions"
    elif [ -d "$HOME/.zsh/completions" ]; then
      zsh_completion_dir="$HOME/.zsh/completions"
    else
      # Fall back to system directories
      for dir in "/usr/local/share/zsh/site-functions" "/usr/share/zsh/site-functions" "/usr/share/zsh/vendor-completions"; do
        if [ -d "$dir" ]; then
          zsh_completion_dir="$dir"
          break
        fi
      done
    fi

    # zsh
    if [ -n "$zsh_completion_dir" ]; then
      # Install Zsh completion file
      mkdir -p "$zsh_completion_dir"
      "$data_dir/emp3r0r-cc" completion zsh | sudo tee "$zsh_completion_dir/_emp3r0r" >/dev/null
      sudo chmod 644 "$zsh_completion_dir/_emp3r0r"
      info "Installed Zsh completion to $zsh_completion_dir/_emp3r0r"
    else
      warn "No suitable Zsh completion directory found"
      warn "You can manually set up Zsh completion by adding this to your ~/.zshrc:"
      # shellcheck disable=SC2154
      warn "  fpath=(/path/to/dir/with/completion $fpath)"
      warn "  autoload -Uz compinit && compinit"
    fi

    # bash
    mkdir -p "/etc/bash_completion.d"
    "$data_dir/emp3r0r-cc" completion bash | sudo tee "/etc/bash_completion.d/emp3r0r" >/dev/null
    sudo chmod 644 "/etc/bash_completion.d/emp3r0r"
    info "Installed Bash completion to /etc/bash_completion.d/emp3r0r"
    info "Restart your bash shell or run 'source /etc/bash_completion.d/emp3r0r'"
  else
    info "Running inside container, skipping setcap, wireguard runtime dir, and autocomplete setup"
  fi

  success "Installed emp3r0r, please check"
  if tmux has-session -t emp3r0r 2>/dev/null; then
    warn "emp3r0r is still running, stopping it in 3 seconds"
    sleep 3
    tmux kill-session -t emp3r0r || error "Failed to kill emp3r0r"
  fi
}

uninstall() {
  if [[ "$EUID" -ne 0 ]]; then
    sudo "$0" --uninstall-only
  else
    do_uninstall
  fi
}

prepare_misc_files() {
  info "Preparing misc files"
  cp -aR "$pwd/tmux" "$temp" || error "cp tmux"
  cp -aR "$pwd/modules" "$temp" || error "cp modules"
  cp -aR "$pwd/emp3r0r" "$temp" || error "cp emp3r0r"
  cp -aR "$pwd/build.sh" "$temp" || error "cp build.sh"
}

create_tar() {
  prepare_misc_files
  info "Creating archive..."
  cd /tmp || error "Cannot cd to /tmp"
  tar -I zstd -cpf "$pwd/emp3r0r.tar.zst" "$temp" || error "failed to create archive"
  success "Packaged emp3r0r"
}

is_in_github_runner() {
  [[ -n "$GITHUB_WORKFLOW" ]] && [[ -n "$GITHUB_ACTION" ]]
}

get_git_version() {
  local version
  if [[ -n "$TAG" ]]; then
    version="$TAG"
  else
    version=$(git describe --tags --always 2>/dev/null)
  fi
  [[ -z "$version" ]] && version="unknown"
  echo "$version"
}

get_version() {
  local version
  local build_time
  build_time=$(date +"%y%m%d%H%M")
  version=$(get_git_version)
  if [[ "$version" = "unknown" ]]; then
    version=$(grep -oP 'Version = "\K[^"]+' ./internal/def/def.go)
  fi
  echo "$version-$build_time"
}

# release or debug
arg1="$1"

case "$1" in
--release)
  (build) && (
    create_tar
  )

  ;;

--debug)
  if build --debug && prepare_misc_files && do_install; then
    package_operator_bundle
    exit 0
  fi
  error "install failed"

  ;;

--build)
  (build) &&
    exit 0

  ;;

--uninstall)
  (uninstall) || error "uninstall failed"
  exit 0

  ;;

--install-only) # install from the release, skipping build
  if do_install; then
    package_operator_bundle
    exit 0
  fi
  error "install failed"

  ;;

--install)
  if build && prepare_misc_files && do_install; then
    package_operator_bundle
    exit 0
  fi
  error "install failed"

  ;;

--package-operator)
  package_operator_bundle
  exit 0

  ;;

*)
  warn "Usage: $0 [--build|--release|--debug|--install|--uninstall]"
  warn "Env: EMP3R0R_DISABLE_GARBLE=1 disables garble for non-debug builds (including --install)"
  warn "Extra: --package-operator builds a portable operator package from an existing install"

  ;;

esac
