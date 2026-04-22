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
    info "zig not found, installing zig to /usr/local/bin ..."
    {
      (test -e zig-linux-x86_64-0.13.0.tar.xz ||
        wget https://ziglang.org/download/0.13.0/zig-linux-x86_64-0.13.0.tar.xz) &&
        tar -xpf zig-linux-x86_64-0.13.0.tar.xz &&
        sudo cp -aR ./zig-linux-x86_64-0.13.0 /usr/local/lib/zig &&
        sudo ln -sf /usr/local/lib/zig/zig /usr/local/bin/zig
    } || error "Failed to install zig"
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

package_operator_bundle() {
  local installed_prefix
  installed_prefix="$(find_installed_prefix)"
  info "Using installed files from $installed_prefix"

  local -a tar_paths
  tar_paths+=("${installed_prefix#/}/bin/emp3r0r")
  tar_paths+=("${installed_prefix#/}/lib/emp3r0r/emp3r0r-cc")
  tar_paths+=("${installed_prefix#/}/lib/emp3r0r/emp3r0r-cat")

  local dir
  for dir in build modules tmux; do
    if [[ -d "$installed_prefix/lib/emp3r0r/$dir" ]]; then
      tar_paths+=("${installed_prefix#/}/lib/emp3r0r/$dir")
    else
      warn "$installed_prefix/lib/emp3r0r/$dir not found; operator package may be incomplete"
    fi
  done

  # Create a tarball of the installed tree only.
  tar --zstd -cpf "$pwd/$operator_bundle_name" -C / "${tar_paths[@]}" || error "failed to create operator package"

  success "Created portable operator package: $pwd/$operator_bundle_name"
  success "Next steps:"
  success "  1. Transfer to your operator environment: $operator_bundle_name"
  success "  2. Install on your operator machine: sudo tar --zstd -xpf $operator_bundle_name -C /"
  success "  3. Run once: sudo setcap cap_net_admin=eip /usr/local/lib/emp3r0r/emp3r0r-cc"
  success "  4. Run emp3r0r server, copy and paste the command from the output to your operator environment"
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
  local extldflags="-static"
  if [[ "$extra_extldflags" == *"-static-pie"* ]]; then
    extldflags="-s"
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
  local build_cmd
  local extldflags="-nostdlib -nodefaultlibs -static"
  [[ "$arg1" != "--debug" ]] && extldflags="-s $extldflags"
  local win_gui_flag=""
  [[ "$arg1" != "--debug" ]] && [[ "$os" == "windows" ]] && win_gui_flag="-H=windowsgui "
  case "$os" in
  windows)
    case "$arch" in
    386)
      build_cmd="CGO_ENABLED=1 CC=\"zig cc -target x86-windows-gnu\" CXX=\"zig c++ -target x86-windows-gnu\" GOOS=$os GOARCH=$arch $gobuild_cmd $build_opt -tags \"netgo emp3r0r_so\" -o \"$temp/$output\" -buildmode c-shared -ldflags=\"${win_gui_flag}$ldflags -linkmode external -extldflags '$extldflags'\""
      ;;
    amd64)
      build_cmd="CGO_ENABLED=1 CC=\"zig cc -target x86_64-windows-gnu\" CXX=\"zig c++ -target x86_64-windows-gnu\" GOOS=$os GOARCH=$arch $gobuild_cmd $build_opt -tags \"netgo emp3r0r_so\" -o \"$temp/$output\" -buildmode c-shared -ldflags=\"${win_gui_flag}$ldflags -linkmode external -extldflags '$extldflags'\""
      ;;
    arm64)
      build_cmd="CGO_ENABLED=1 CC=\"zig cc -target aarch64-windows-gnu\" CXX=\"zig c++ -target aarch64-windows-gnu\" GOOS=$os GOARCH=$arch $gobuild_cmd $build_opt -tags \"netgo emp3r0r_so\" -o \"$temp/$output\" -buildmode c-shared -ldflags=\"${win_gui_flag}$ldflags -linkmode external -extldflags '$extldflags'\""
      ;;
    esac
    ;;
  linux)
    case "$arch" in
    386)
      build_cmd="CGO_ENABLED=1 CC=\"zig cc -target x86-linux-gnu\" GOARCH=$arch $gobuild_cmd $build_opt -tags emp3r0r_so -o \"$temp/$output\" -buildmode c-shared -ldflags=\"$ldflags -linkmode external -extldflags '$extldflags'\""
      ;;
    amd64)
      build_cmd="CGO_ENABLED=1 CC=\"zig cc -target x86_64-linux-gnu\" GOARCH=$arch $gobuild_cmd $build_opt -tags emp3r0r_so -o \"$temp/$output\" -buildmode c-shared -ldflags=\"$ldflags -linkmode external -extldflags '$extldflags'\""
      ;;
    arm)
      build_cmd="CGO_ENABLED=1 CC=\"zig cc -target arm-linux-gnueabi\" GOARCH=$arch $gobuild_cmd $build_opt -tags emp3r0r_so -o \"$temp/$output\" -buildmode c-shared -ldflags=\"$ldflags -linkmode external -extldflags '$extldflags'\""
      ;;
    arm64)
      build_cmd="CGO_ENABLED=1 CC=\"zig cc -target aarch64-linux-gnu\" GOARCH=$arch $gobuild_cmd $build_opt -tags emp3r0r_so -o \"$temp/$output\" -buildmode c-shared -ldflags=\"$ldflags -linkmode external -extldflags '$extldflags'\""
      ;;
    riscv64)
      # the built shared object is untested
      build_cmd="CGO_ENABLED=1 CC=\"zig cc -target riscv64-linux-musl\" GOARCH=$arch $gobuild_cmd $build_opt -tags emp3r0r_so -o \"$temp/$output\" -buildmode c-shared -ldflags=\"$ldflags -linkmode external -extldflags '$extldflags'\""
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

build() {
  # build
  # -----
  check_required_go
  check_disk_space
  $GO_BIN mod tidy || error "go mod tidy"

  # Check for zig installation
  check_zig

  ldflags="-v -X 'github.com/jm33-m0/emp3r0r/core/internal/def.MagicString=$magic_str'"
  ldflags+=" -X 'github.com/jm33-m0/emp3r0r/core/internal/def.Version=$(get_version)'"
  if [[ "$1" = "--debug" ]]; then
    gobuild_cmd="$GO_BIN"
    build_opt="build"
  else
    if [[ "$disable_garble" = "1" || "$disable_garble" = "true" || "$disable_garble" = "yes" ]]; then
      gobuild_cmd="$GO_BIN"
      build_opt="build"
      ldflags+=" -s -w"
      info "Garble disabled by EMP3R0R_DISABLE_GARBLE=$disable_garble, using plain go build"
    else
      gobuild_cmd="garble"
      build_opt="-tiny -seed=random build"
      ldflags+=" -s -w"
      info "Setting up garble"
      $GO_BIN install mvdan.cc/garble@master || error "Failed to install garble"
    fi
  fi

  info "Building CC"
  {
    cd cmd/cc && CGO_ENABLED=0 $GO_BIN build -o "$temp/cc.exe" -ldflags="$ldflags"
  } || error "build cc"
  info "Building cat"
  {
    cd "$pwd/cmd/cat" && CGO_ENABLED=0 $GO_BIN build -o "$temp/cat.exe" -ldflags="$ldflags"
  } || error "build cat"
  info "Building listener"
  {
    cd "$pwd/cmd/listener" && CGO_ENABLED=0 $GO_BIN build -o "$temp/listener.exe" -ldflags="$ldflags"
  } || error "build listener"

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

  # set capabilities for cc
  setcap cap_net_admin=eip "$data_dir/emp3r0r-cc" || error "setcap"

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
  tar --zstd -cpf "$pwd/emp3r0r.tar.zst" "$temp" || error "failed to create archive"
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

  (build --debug) && (
    create_tar
  )

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
  exit 0

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
