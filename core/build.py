#!/usr/bin/env python3
from __future__ import annotations

"""
emp3r0r Core Build and Installation Script (Python)
---------------------------------------------------
Builds C2 server binaries (CC, cat, listener), agent stubs (pure Go & CGO),
shared objects, BOFs, and custom modules. Performs local system installation,
operator bundle packaging, and uninstallation.

Usage:
  python3 build.py [COMMAND]

Commands:
  --build             Build binaries and agent stubs in temp directory
  --install           Build binaries, install to system prefix, package operator bundle
  --install-only      Skip build; install pre-built binaries and package operator bundle
  --debug             Build with debug mode (no garble), install, package operator bundle
  --release           Build and package full release tarball (emp3r0r.tar.zst)
  --uninstall         Remove installed files and completions from install prefix
  --package-operator  Package existing installed files into emp3r0r-operator-kit.tar.zst

Environment variables:
  EMP3R0R_DISABLE_GARBLE=1   Disable garble obfuscation for non-debug builds
  PREFIX=/usr/local          Custom install prefix
"""

import argparse
import hashlib
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.request

DONUT_URL = "https://github.com/TheWover/donut/releases/download/v1.1/donut_v1.1.tar.gz"
DONUT_ARCHIVE_NAME = "donut_v1.1.tar.gz"
REQUIRED_GO_VERSION = "1.26.2"
REQUIRED_FREE_KB = 10 * 1024 * 1024  # 10 GB

USE_COLOR = sys.stdout.isatty() and not os.environ.get("NO_COLOR")
IS_DRY_RUN = os.environ.get("EMP3R0R_DRY_RUN", "0").lower() in ("1", "true", "yes")


def _fmt(text: str, color_code: str) -> str:
    if USE_COLOR:
        return f"\033[{color_code}m{text}\033[0m"
    return text


def log_success(msg: str) -> None:
    print(f"\n{_fmt(f'[SUCCESS] {msg}', '32')}\n")


def log_info(msg: str) -> None:
    print(_fmt(f"[INFO] {msg}", "34"))


def log_warn(msg: str) -> None:
    print(_fmt(f"[WARN] {msg}", "33"))


def log_error(msg: str, exit_code: int = 1) -> None:
    print(f"\n{_fmt(f'[ERROR] {msg}', '31')}\n", file=sys.stderr)
    sys.exit(exit_code)


def run_cmd(
    cmd: list[str] | str,
    check: bool = True,
    cwd: pathlib.Path | str | None = None,
    env: dict[str, str] | None = None,
    capture_output: bool = False,
    text: bool = True,
    shell: bool = False,
) -> subprocess.CompletedProcess:
    cmd_str = cmd if isinstance(cmd, str) else " ".join(cmd)
    if IS_DRY_RUN:
        print(_fmt(f"[DRY-RUN] Would execute: {cmd_str} (cwd: {cwd or '.'})", "36"))
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    try:
        return subprocess.run(
            cmd,
            check=check,
            cwd=cwd,
            env=env,
            capture_output=capture_output,
            text=text,
            shell=shell,
        )
    except subprocess.CalledProcessError as e:
        if not check:
            raise e
        log_error(f"Command failed (exit code {e.returncode}): {cmd_str}")
        raise e


def download_file(url: str, dest: pathlib.Path) -> bool:
    try:
        log_info(f"Downloading {url} to {dest}...")
        urllib.request.urlretrieve(url, str(dest))
        return True
    except Exception as e:
        log_warn(f"Failed to download via urllib ({e}). Trying curl/wget...")
        if shutil.which("curl"):
            res = run_cmd(["curl", "-sSL", "--connect-timeout", "15", url, "-o", str(dest)], check=False)
            return res.returncode == 0
        elif shutil.which("wget"):
            res = run_cmd(["wget", "-qO", str(dest), url], check=False)
            return res.returncode == 0
        return False


def get_git_version() -> str:
    env_tag = os.environ.get("TAG")
    if env_tag:
        return env_tag
    res = run_cmd(["git", "describe", "--tags", "--always"], check=False, capture_output=True)
    if res.returncode == 0 and res.stdout.strip():
        return res.stdout.strip()
    return "unknown"


def get_version(core_dir: pathlib.Path) -> str:
    build_time = time.strftime("%y%m%d%H%M")
    version = get_git_version()
    if version == "unknown":
        def_file = core_dir / "internal" / "def" / "def.go"
        if def_file.exists():
            content = def_file.read_text(encoding="utf-8")
            match = re.search(r'Version\s*=\s*"([^"]+)"', content)
            if match:
                version = match.group(1)
    return f"{version}-{build_time}"


def check_required_go() -> str:
    go_bin = shutil.which("go")
    if not go_bin:
        msg = f"You need to set up Go {REQUIRED_GO_VERSION} first"
        if IS_DRY_RUN:
            log_warn(f"[DRY-RUN] {msg}")
            go_bin = "go"
        else:
            log_error(msg)

    res = run_cmd([go_bin, "version"], check=False, capture_output=True)
    current_ver = ""
    if res.returncode == 0:
        parts = res.stdout.strip().split()
        if len(parts) >= 3:
            current_ver = parts[2].removeprefix("go")

    if current_ver != REQUIRED_GO_VERSION:
        log_warn(f"Go {REQUIRED_GO_VERSION} is recommended, found {current_ver}")

    goroot = pathlib.Path("/usr/local/go")
    gopath = pathlib.Path(os.environ.get("GOPATH", pathlib.Path.home() / "go"))

    os.environ["GOROOT"] = str(goroot)
    os.environ["GOTOOLCHAIN"] = "local"

    path_entries = os.environ.get("PATH", "").split(os.path.pathsep)
    new_paths = []
    if (goroot / "bin").exists():
        new_paths.append(str(goroot / "bin"))
    if (gopath / "bin").exists():
        new_paths.append(str(gopath / "bin"))
    for p in path_entries:
        if p not in new_paths:
            new_paths.append(p)
    os.environ["PATH"] = os.path.pathsep.join(new_paths)

    official_go = goroot / "bin" / "go"
    actual_go = str(official_go) if official_go.is_file() and os.access(official_go, os.X_OK) else go_bin
    log_info(f"Using Go toolchain: {actual_go} (version {current_ver})")
    return actual_go


def check_disk_space(core_dir: pathlib.Path) -> None:
    for check_path in [core_dir, pathlib.Path("/")]:
        try:
            stat = shutil.disk_usage(check_path)
            avail_kb = stat.free // 1024
            if avail_kb < REQUIRED_FREE_KB:
                avail_gb = avail_kb / (1024 * 1024)
                log_warn(
                    f"{check_path} only has {avail_gb:.2f}GB available. "
                    "Installation might fail due to garble's huge cache."
                )
        except Exception as e:
            log_warn(f"Failed to check disk space for {check_path}: {e}")
    log_info("Disk space check passed: at least 10GB free for build and temp files")


def check_zig() -> None:
    if not shutil.which("zig"):
        msg = "zig not found. Please run build inside the builder container, or install zig 0.13.0 manually on the host."
        if IS_DRY_RUN:
            log_warn(f"[DRY-RUN] {msg}")
        else:
            log_error(msg)
    else:
        log_info("zig is already installed")


def check_build_toolchain() -> None:
    required = ["make", "clang", "gcc"]
    missing = []
    for tool in required:
        if not shutil.which(tool):
            missing.append(tool)

    has_mingw = shutil.which("x86_64-w64-mingw32-gcc") or shutil.which("i686-w64-mingw32-gcc")
    if not has_mingw:
        missing.append("mingw-w64")

    if missing:
        unique_missing = list(dict.fromkeys(missing))
        msg = (
            f"Missing required toolchains: {' '.join(unique_missing)}. "
            "Please run build inside the builder container, or install them manually on the host."
        )
        if IS_DRY_RUN:
            log_warn(f"[DRY-RUN] {msg}")
        else:
            log_error(msg)


def install_donut(target_dir: pathlib.Path, search_dir: pathlib.Path | None = None) -> None:
    donut_archive = None
    if search_dir and (search_dir / DONUT_ARCHIVE_NAME).is_file():
        donut_archive = search_dir / DONUT_ARCHIVE_NAME

    if not donut_archive or not donut_archive.is_file():
        tmp_archive = pathlib.Path(tempfile.gettempdir()) / DONUT_ARCHIVE_NAME
        if download_file(DONUT_URL, tmp_archive):
            donut_archive = tmp_archive

    if donut_archive and donut_archive.is_file():
        log_info("Extracting and installing donut...")
        with tempfile.TemporaryDirectory(prefix="donut-extract-") as tmp_dir:
            tmp_path = pathlib.Path(tmp_dir)
            res = run_cmd(["tar", "-xzf", str(donut_archive), "-C", str(tmp_path)], check=False)
            if res.returncode == 0:
                donut_bin = None
                for p in tmp_path.rglob("donut"):
                    if p.is_file():
                        donut_bin = p
                        break
                if donut_bin:
                    bin_target = target_dir / "bin"
                    bin_target.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(donut_bin, bin_target / "donut")
                    (bin_target / "donut").chmod(0o755)

                    usr_local_bin = pathlib.Path("/usr/local/bin")
                    usr_local_bin.mkdir(parents=True, exist_ok=True)
                    symlink = usr_local_bin / "donut"
                    if symlink.is_symlink() or symlink.exists():
                        symlink.unlink(missing_ok=True)
                    try:
                        symlink.symlink_to(bin_target / "donut")
                        log_info("Linked donut executable to /usr/local/bin/donut")
                    except Exception as e:
                        log_warn(f"Could not symlink /usr/local/bin/donut: {e}")
                else:
                    log_warn(f"Executable 'donut' not found inside {donut_archive}")
            else:
                log_warn(f"Failed to extract {donut_archive}")
    else:
        log_warn("Donut archive could not be obtained; skipping donut installation")


def build_agent_pure(
    arch: str,
    os_name: str,
    output: str,
    extra_flags: str,
    extra_extldflags: str,
    arg1: str,
    ldflags: str,
    temp_dir: pathlib.Path,
    core_dir: pathlib.Path,
    gobuild_cmd: str,
    build_opt: str,
) -> None:
    log_info(f"Building pure agent stub for {os_name} {arch}")

    tags = "netgo agent" if arg1 == "--debug" else "netgo release agent"
    win_gui_flag = "-H=windowsgui " if (arg1 != "--debug" and os_name == "windows") else ""

    current_ldflags = ldflags
    if extra_extldflags:
        current_ldflags += f" -extldflags '{extra_extldflags}'"

    out_file = temp_dir / output
    env = os.environ.copy()
    env["CGO_ENABLED"] = "0"
    env["GOARCH"] = arch
    env["GOOS"] = os_name

    cmd_str = (
        f"{gobuild_cmd} {build_opt} {extra_flags} -trimpath -buildvcs=false "
        f"-tags '{tags}' -o \"{out_file}\" -ldflags=\"{win_gui_flag}{current_ldflags}\""
    )

    print(f"Running: CGO_ENABLED=0 GOARCH={arch} GOOS={os_name} {cmd_str}")
    agent_cmd_dir = core_dir / "cmd" / "agent"
    res = run_cmd(cmd_str, check=False, cwd=agent_cmd_dir, env=env, shell=True)
    if res.returncode != 0:
        log_error(f"Failed to build pure agent stub for {os_name} {arch}")


def build_agent_cgo(
    arch: str,
    os_name: str,
    output: str,
    extra_flags: str,
    extra_extldflags: str,
    arg1: str,
    ldflags: str,
    temp_dir: pathlib.Path,
    core_dir: pathlib.Path,
    gobuild_cmd: str,
    build_opt: str,
) -> None:
    log_info(f"Building CGO agent stub for {os_name} {arch}")

    tags = "netgo agent" if arg1 == "--debug" else "netgo release agent"

    cc_targets = {
        "amd64": "x86_64-linux-musl",
        "386": "x86-linux-musl",
        "arm64": "aarch64-linux-musl",
        "riscv64": "riscv64-linux-musl",
    }
    target = cc_targets.get(arch)
    cc_cmd = f"zig cc -target {target}" if target else "musl-gcc"

    extldflags = "-static -Wl,--gc-sections"
    if "-static-pie" in extra_extldflags:
        extldflags = "-s -Wl,--gc-sections"
    if arg1 != "--debug":
        extldflags += " -s"
    if extra_extldflags:
        extldflags += f" {extra_extldflags}"

    out_file = temp_dir / output
    env = os.environ.copy()
    env["CGO_ENABLED"] = "1"
    env["CC"] = cc_cmd
    env["GOARCH"] = arch
    env["GOOS"] = os_name

    cmd_str = (
        f"{gobuild_cmd} {build_opt} {extra_flags} -trimpath -buildvcs=false "
        f"-tags '{tags}' -o \"{out_file}\" -ldflags=\"{ldflags} -linkmode external -extldflags '{extldflags}'\""
    )

    print(f"Running: CGO_ENABLED=1 CC=\"{cc_cmd}\" GOARCH={arch} GOOS={os_name} {cmd_str}")
    agent_cmd_dir = core_dir / "cmd" / "agent"
    res = run_cmd(cmd_str, check=False, cwd=agent_cmd_dir, env=env, shell=True)
    if res.returncode != 0:
        log_error(f"Failed to build CGO agent stub for {os_name} {arch}")


def build_shared_object(
    arch: str,
    os_name: str,
    output: str,
    arg1: str,
    ldflags: str,
    temp_dir: pathlib.Path,
    core_dir: pathlib.Path,
    gobuild_cmd: str,
    build_opt: str,
) -> None:
    log_info(f"Building shared object for {os_name} {arch}")

    tags = "emp3r0r_so" if arg1 == "--debug" else "release emp3r0r_so"
    extldflags = "-nostdlib -nodefaultlibs -Wl,--gc-sections"
    if arg1 != "--debug":
        extldflags = f"-s {extldflags}"

    win_gui_flag = "-H=windowsgui " if (arg1 != "--debug" and os_name == "windows") else ""
    out_file = temp_dir / output

    env = os.environ.copy()
    env["CGO_ENABLED"] = "1"
    env["GOOS"] = os_name
    env["GOARCH"] = arch

    if os_name == "windows":
        tags = f"netgo {tags}"
        zig_target = {
            "386": "x86-windows-gnu",
            "amd64": "x86_64-windows-gnu",
            "arm64": "aarch64-windows-gnu",
        }.get(arch, "x86_64-windows-gnu")
        env["CC"] = f"zig cc -target {zig_target}"
        env["CXX"] = f"zig c++ -target {zig_target}"
    elif os_name == "linux":
        zig_target = {
            "386": "x86-linux-gnu.2.17",
            "arm": "arm-linux-gnueabihf.2.17",
            "arm64": "aarch64-linux-gnu.2.17",
            "riscv64": "riscv64-linux-musl",
        }.get(arch)
        if zig_target:
            env["CC"] = f"zig cc -target {zig_target}"

    cmd_str = (
        f"{gobuild_cmd} {build_opt} -trimpath -buildvcs=false -tags \"{tags}\" "
        f"-o \"{out_file}\" -buildmode c-shared -ldflags=\"{win_gui_flag}{ldflags} -linkmode external -extldflags '{extldflags}'\""
    )

    print(f"Running shared object build for {os_name} {arch}: {cmd_str}")
    agent_cmd_dir = core_dir / "cmd" / "agent"
    res = run_cmd(cmd_str, check=False, cwd=agent_cmd_dir, env=env, shell=True)
    if res.returncode != 0:
        log_error(f"Failed to build shared object for {os_name} {arch}")


def build(arg1: str, temp_dir: pathlib.Path, core_dir: pathlib.Path) -> None:
    check_build_toolchain()
    go_bin = check_required_go()
    check_disk_space(core_dir)

    vendor_dir = core_dir / "vendor"
    mod_txt = vendor_dir / "modules.txt"

    if vendor_dir.is_dir() and mod_txt.is_file():
        log_info("Using existing vendor/ directory for local modules")
        mod_opt = "-mod=vendor"
    else:
        log_info("vendor/ directory missing or incomplete, attempting to vendor dependencies...")
        res = run_cmd([go_bin, "mod", "vendor"], check=False, cwd=core_dir)
        if res.returncode == 0:
            log_info("Successfully vendored modules")
            mod_opt = "-mod=vendor"
        else:
            log_warn("go mod vendor failed; falling back to default Go module resolution")
            mod_opt = ""

    check_zig()

    magic_str = hashlib.sha256(os.urandom(32)).hexdigest()
    version = get_version(core_dir)

    ldflags = (
        f"-v -X 'github.com/jm33-m0/emp3r0r/core/internal/def.MagicString={magic_str}' "
        f"-X 'github.com/jm33-m0/emp3r0r/core/internal/def.Version={version}'"
    )

    disable_garble = os.environ.get("EMP3R0R_DISABLE_GARBLE", "0").lower() in ("1", "true", "yes")

    if arg1 == "--debug":
        gobuild_cmd = go_bin
        build_opt = f"build {mod_opt}".strip()
    else:
        if disable_garble:
            gobuild_cmd = go_bin
            build_opt = f"build {mod_opt}".strip()
            ldflags += " -s -w"
            log_info("Garble disabled by EMP3R0R_DISABLE_GARBLE, using plain go build")
        else:
            gobuild_cmd = "garble"
            build_opt = f"-tiny -seed=random build {mod_opt}".strip()
            ldflags += " -s -w"
            log_info("Using garble for obfuscation")
            if not shutil.which("garble"):
                log_error("garble not found. It should be installed in the builder container.")

    # Build CC
    log_info("Building CC")
    env_cgo0 = os.environ.copy()
    env_cgo0["CGO_ENABLED"] = "0"
    cc_cmd = f"{go_bin} build {mod_opt} -buildvcs=false -o \"{temp_dir / 'cc.exe'}\" -ldflags=\"{ldflags}\""
    res = run_cmd(cc_cmd, check=False, cwd=core_dir / "cmd" / "cc", env=env_cgo0, shell=True)
    if res.returncode != 0:
        log_error("Failed to build CC")

    # Build cat
    log_info("Building cat")
    cat_cmd = f"{go_bin} build {mod_opt} -buildvcs=false -o \"{temp_dir / 'cat.exe'}\" -ldflags=\"{ldflags}\""
    res = run_cmd(cat_cmd, check=False, cwd=core_dir / "cmd" / "cat", env=env_cgo0, shell=True)
    if res.returncode != 0:
        log_error("Failed to build cat")

    # Build listener
    log_info("Building listener")
    listener_cmd = f"{go_bin} build {mod_opt} -buildvcs=false -o \"{temp_dir / 'listener.exe'}\" -ldflags=\"{ldflags}\""
    res = run_cmd(listener_cmd, check=False, cwd=core_dir / "cmd" / "listener", env=env_cgo0, shell=True)
    if res.returncode != 0:
        log_error("Failed to build listener")

    if arg1 != "--debug":
        ldflags += " -buildid="

    pie_flags = "-buildmode=pie"
    ext_pie = "-static-pie"

    # Agent stubs
    build_agent_cgo("amd64", "linux", "stub-amd64", pie_flags, ext_pie, arg1, ldflags, temp_dir, core_dir, gobuild_cmd, build_opt)
    build_agent_cgo("386", "linux", "stub-386", pie_flags, ext_pie, arg1, ldflags, temp_dir, core_dir, gobuild_cmd, build_opt)
    build_agent_pure("arm", "linux", "stub-arm", "", "", arg1, ldflags, temp_dir, core_dir, gobuild_cmd, build_opt)
    build_agent_cgo("arm64", "linux", "stub-arm64", pie_flags, ext_pie, arg1, ldflags, temp_dir, core_dir, gobuild_cmd, build_opt)

    build_agent_pure("mips", "linux", "stub-mips", "", "", arg1, ldflags, temp_dir, core_dir, gobuild_cmd, build_opt)
    build_agent_pure("mips64", "linux", "stub-mips64", "", "", arg1, ldflags, temp_dir, core_dir, gobuild_cmd, build_opt)

    build_agent_cgo("riscv64", "linux", "stub-riscv64", pie_flags, ext_pie, arg1, ldflags, temp_dir, core_dir, gobuild_cmd, build_opt)
    build_agent_pure("ppc64", "linux", "stub-ppc64", "", "", arg1, ldflags, temp_dir, core_dir, gobuild_cmd, build_opt)

    # Windows stubs
    build_agent_pure("amd64", "windows", "stub-win-amd64", "", "", arg1, ldflags, temp_dir, core_dir, gobuild_cmd, build_opt)
    build_agent_pure("386", "windows", "stub-win-386", "", "", arg1, ldflags, temp_dir, core_dir, gobuild_cmd, build_opt)
    build_agent_pure("arm64", "windows", "stub-win-arm64", "", "", arg1, ldflags, temp_dir, core_dir, gobuild_cmd, build_opt)

    # Shared Objects
    build_shared_object("amd64", "windows", "stub-win-amd64.dll", arg1, ldflags, temp_dir, core_dir, gobuild_cmd, build_opt)
    build_shared_object("386", "windows", "stub-win-386.dll", arg1, ldflags, temp_dir, core_dir, gobuild_cmd, build_opt)
    build_shared_object("arm64", "windows", "stub-win-arm64.dll", arg1, ldflags, temp_dir, core_dir, gobuild_cmd, build_opt)
    build_shared_object("amd64", "linux", "stub-amd64.so", arg1, ldflags, temp_dir, core_dir, gobuild_cmd, build_opt)
    build_shared_object("386", "linux", "stub-386.so", arg1, ldflags, temp_dir, core_dir, gobuild_cmd, build_opt)
    build_shared_object("arm", "linux", "stub-arm.so", arg1, ldflags, temp_dir, core_dir, gobuild_cmd, build_opt)
    build_shared_object("riscv64", "linux", "stub-riscv64.so", arg1, ldflags, temp_dir, core_dir, gobuild_cmd, build_opt)

    # Build modules with a make_all.sh wrapper.
    # EMP3R0R_DEBUG is passed to every module so any module that supports a
    # debug build (e.g. coffloader's -DDEBUG) can opt in for --debug builds.
    log_info("Building complex modules with make_all.sh...")
    modules_dir = core_dir / "modules"
    module_env = os.environ.copy()
    module_env["EMP3R0R_DEBUG"] = "1" if arg1 == "--debug" else "0"
    if modules_dir.is_dir():
        for mod_dir in modules_dir.iterdir():
            make_all = mod_dir / "make_all.sh"
            if mod_dir.is_dir() and make_all.is_file():
                log_info(f"Running make_all.sh in {mod_dir.name} ({'debug' if arg1 == '--debug' else 'release'})")
                try:
                    make_all.chmod(0o755)
                except Exception:
                    pass
                res = run_cmd(["./make_all.sh"], check=False, cwd=mod_dir, env=module_env)
                if res.returncode != 0:
                    log_warn(f"Failed to build modules in {mod_dir.name} via make_all.sh")

    log_info("Building Linux test BOFs")
    hello_linux = modules_dir / "hello_linux"
    if hello_linux.is_dir():
        res = run_cmd(["make", "-C", str(hello_linux)], check=False)
        if res.returncode != 0:
            log_warn("Failed to build hello_linux module")


def find_installed_prefix(prefix: str) -> pathlib.Path:
    detected = pathlib.Path(prefix)
    if not (detected / "lib" / "emp3r0r" / "emp3r0r-cc").is_file():
        for candidate in [pathlib.Path("/usr/local"), pathlib.Path("/usr")]:
            if (candidate / "lib" / "emp3r0r" / "emp3r0r-cc").is_file():
                detected = candidate
                break

    if not (detected / "lib" / "emp3r0r" / "emp3r0r-cc").is_file():
        log_error("emp3r0r is not installed. Please run --install on the C2 server first")

    return detected


def package_operator_bundle(prefix: str, core_dir: pathlib.Path) -> None:
    installed_prefix = find_installed_prefix(prefix)
    log_info(f"Using installed files from {installed_prefix}")

    with tempfile.TemporaryDirectory(prefix="emp3r0r-operator-bundle-") as bundle_stage:
        stage_path = pathlib.Path(bundle_stage)
        kit_dir = stage_path / "emp3r0r-operator-kit"
        kit_dir.mkdir(parents=True, exist_ok=True)

        bin_src = installed_prefix / "bin" / "emp3r0r"
        lib_src = installed_prefix / "lib" / "emp3r0r"

        (kit_dir / "bin").mkdir(parents=True, exist_ok=True)
        (kit_dir / "lib" / "emp3r0r").mkdir(parents=True, exist_ok=True)

        if bin_src.exists():
            shutil.copy2(bin_src, kit_dir / "bin" / "emp3r0r")
        else:
            log_error("Failed to copy emp3r0r launcher")

        for binary in ["emp3r0r-cc", "emp3r0r-cat"]:
            src = lib_src / binary
            if src.exists():
                shutil.copy2(src, kit_dir / "lib" / "emp3r0r" / binary)
            else:
                log_error(f"Failed to copy {binary}")

        listener_src = installed_prefix / "bin" / "emp3r0r-listener"
        if listener_src.exists():
            shutil.copy2(listener_src, kit_dir / "bin" / "emp3r0r-listener")
        else:
            log_warn(f"emp3r0r-listener not found at {listener_src}; skipping")

        for d in ["build", "modules", "tmux"]:
            src_dir = lib_src / d
            if src_dir.is_dir():
                shutil.copytree(src_dir, kit_dir / "lib" / "emp3r0r" / d, dirs_exist_ok=True)
            else:
                log_warn(f"{src_dir} not found; operator package may be incomplete")

        log_info(f"Downloading donut package from {DONUT_URL}...")
        download_file(DONUT_URL, kit_dir / DONUT_ARCHIVE_NAME)
        install_donut(kit_dir / "lib" / "emp3r0r", search_dir=kit_dir)

        # Copy Python installer directly from repo root
        root_install_py = core_dir.parent / "install.py"
        if root_install_py.is_file():
            shutil.copy2(root_install_py, kit_dir / "install.py")
            try:
                (kit_dir / "install.py").chmod(0o755)
            except Exception:
                pass
            log_info("Included install.py in operator kit")
        else:
            log_error(f"Root install.py not found at {root_install_py}")

        operator_bundle_name = "emp3r0r-operator-kit.tar.zst"
        bundle_tar = core_dir / operator_bundle_name
        res = run_cmd(
            ["tar", "-I", "zstd", "-cpf", str(bundle_tar), "-C", str(stage_path), "emp3r0r-operator-kit"],
            check=False,
        )
        if res.returncode != 0:
            log_error("Failed to create operator package")

        log_success(f"Created portable operator package: {bundle_tar}")
        log_success("Transfer to your operator machine, then:")
        log_success(f"  tar -I zstd -xpf {operator_bundle_name} && ./emp3r0r-operator-kit/install.py")


def do_install(prefix: str, temp_dir: pathlib.Path, core_dir: pathlib.Path) -> None:
    if not IS_DRY_RUN and os.name != "nt" and hasattr(os, "geteuid") and os.geteuid() != 0:
        log_error("You must be root to install emp3r0r")

    log_info(f"emp3r0r will be installed to {prefix}")

    if not shutil.which("tmux") and not IS_DRY_RUN:
        log_error("tmux not found")

    if shutil.which("tmux") or IS_DRY_RUN:
        res = run_cmd(["tmux", "has-session", "-t", "emp3r0r"], check=False)
        if res.returncode == 0 or IS_DRY_RUN:
            run_cmd(["tmux", "kill-session", "-t", "emp3r0r"], check=False)

    data_dir = pathlib.Path(prefix) / "lib" / "emp3r0r"
    bin_dir = pathlib.Path(prefix) / "bin"
    build_dir = data_dir / "build"

    if not IS_DRY_RUN:
        build_dir.mkdir(parents=True, exist_ok=True)
        bin_dir.mkdir(parents=True, exist_ok=True)

    if not IS_DRY_RUN:
        if (temp_dir / "tmux").is_dir():
            shutil.copytree(temp_dir / "tmux", data_dir / "tmux", dirs_exist_ok=True)
        if (temp_dir / "modules").is_dir():
            shutil.copytree(temp_dir / "modules", data_dir / "modules", dirs_exist_ok=True)

        for stub in temp_dir.glob("stub*"):
            shutil.copy2(stub, build_dir / stub.name)

        tmux_conf = data_dir / "tmux" / ".tmux.conf"
        if tmux_conf.is_file():
            tmux_sh_dir = str(data_dir / "tmux" / "sh")
            content = tmux_conf.read_text(encoding="utf-8")
            content = content.replace("~/sh", tmux_sh_dir)
            tmux_conf.write_text(content, encoding="utf-8")

        if (temp_dir / "cc.exe").is_file():
            (temp_dir / "cc.exe").chmod(0o755)
        if (temp_dir / "cat.exe").is_file():
            (temp_dir / "cat.exe").chmod(0o755)

        if (temp_dir / "emp3r0r").is_file():
            shutil.copy2(temp_dir / "emp3r0r", bin_dir / "emp3r0r")
            (bin_dir / "emp3r0r").chmod(0o755)
        if (temp_dir / "listener.exe").is_file():
            shutil.copy2(temp_dir / "listener.exe", bin_dir / "emp3r0r-listener")
            (bin_dir / "emp3r0r-listener").chmod(0o755)

        if (temp_dir / "cc.exe").is_file():
            shutil.copy2(temp_dir / "cc.exe", data_dir / "emp3r0r-cc")
            (data_dir / "emp3r0r-cc").chmod(0o755)
        if (temp_dir / "cat.exe").is_file():
            shutil.copy2(temp_dir / "cat.exe", data_dir / "emp3r0r-cat")
            (data_dir / "emp3r0r-cat").chmod(0o755)

    install_donut(data_dir, search_dir=temp_dir)

    is_container = pathlib.Path("/.dockerenv").exists() or pathlib.Path("/run/.containerenv").exists()

    if not is_container:
        log_info("Setting capabilities for emp3r0r-cc...")
        run_cmd(["setcap", "cap_net_admin=eip", str(data_dir / "emp3r0r-cc")])

        if not IS_DRY_RUN:
            wg_dir = pathlib.Path("/var/run/wireguard")
            try:
                wg_dir.mkdir(parents=True, exist_ok=True)
                wg_dir.chmod(0o755)
                current_user = os.environ.get("SUDO_USER") or os.environ.get("USER") or "root"
                shutil.chown(wg_dir, user=current_user, group=current_user)
            except Exception:
                pass

            tmpfiles = pathlib.Path("/etc/tmpfiles.d")
            if tmpfiles.is_dir():
                current_user = os.environ.get("SUDO_USER") or os.environ.get("USER") or "root"
                (tmpfiles / "emp3r0r-wireguard.conf").write_text(
                    f"d /var/run/wireguard 0755 {current_user} {current_user}\n", encoding="utf-8"
                )

        cc_bin = data_dir / "emp3r0r-cc"
        bash_comp_dir = pathlib.Path("/etc/bash_completion.d")
        if bash_comp_dir.is_dir():
            res = run_cmd([str(cc_bin), "completion", "bash"], check=False, capture_output=True)
            if res.returncode == 0 and res.stdout:
                (bash_comp_dir / "emp3r0r").write_text(res.stdout, encoding="utf-8")
                (bash_comp_dir / "emp3r0r").chmod(0o644)
                log_info("Installed Bash completion to /etc/bash_completion.d/emp3r0r")
    else:
        log_info("Running inside container, skipping setcap, wireguard runtime dir, and autocomplete setup")

    log_success("Installed emp3r0r, please check")


def do_uninstall(prefix: str) -> None:
    if os.geteuid() != 0:
        log_error("You must be root to uninstall emp3r0r")

    log_info(f"emp3r0r will be uninstalled from {prefix}")

    data_dir = pathlib.Path(prefix) / "lib" / "emp3r0r"
    bin_dir = pathlib.Path(prefix) / "bin"

    if data_dir.exists():
        shutil.rmtree(data_dir, ignore_errors=True)
    if (bin_dir / "emp3r0r").exists():
        (bin_dir / "emp3r0r").unlink(missing_ok=True)
    if (bin_dir / "emp3r0r-listener").exists():
        (bin_dir / "emp3r0r-listener").unlink(missing_ok=True)

    bash_comp = pathlib.Path("/etc/bash_completion.d/emp3r0r")
    bash_comp.unlink(missing_ok=True)

    for zsh_dir in [
        pathlib.Path("/usr/local/share/zsh/site-functions"),
        pathlib.Path("/usr/share/zsh/site-functions"),
        pathlib.Path("/usr/share/zsh/vendor-completions"),
        pathlib.Path.home() / ".zsh" / "completions",
    ]:
        zsh_comp = zsh_dir / "_emp3r0r"
        if zsh_comp.exists():
            zsh_comp.unlink(missing_ok=True)
            log_info(f"Removed Zsh completion from {zsh_dir}")

    log_success("emp3r0r has been removed")


def prepare_misc_files(core_dir: pathlib.Path, temp_dir: pathlib.Path) -> None:
    log_info("Preparing misc files")
    for name in ["tmux", "modules", "emp3r0r"]:
        src = core_dir / name
        if src.exists():
            if src.is_dir():
                shutil.copytree(src, temp_dir / name, dirs_exist_ok=True)
            else:
                shutil.copy2(src, temp_dir / name)

    build_py = core_dir / "build.py"
    if build_py.exists():
        shutil.copy2(build_py, temp_dir / "build.py")


def create_tar(core_dir: pathlib.Path, temp_dir: pathlib.Path) -> None:
    prepare_misc_files(core_dir, temp_dir)
    log_info("Creating archive...")
    release_tar = core_dir / "emp3r0r.tar.zst"
    res = run_cmd(
        ["tar", "-I", "zstd", "-cpf", str(release_tar), "-C", str(temp_dir.parent), temp_dir.name],
        check=False,
    )
    if res.returncode != 0:
        log_error("Failed to create archive")
    log_success("Packaged emp3r0r")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="emp3r0r Core Build and Installation Script",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--build", action="store_true", help="Build binaries and agent stubs in temp directory")
    group.add_argument("--install", action="store_true", help="Build binaries, install to prefix, package operator bundle")
    group.add_argument("--install-only", action="store_true", help="Skip build; install pre-built binaries")
    group.add_argument("--debug", action="store_true", help="Build with debug mode (no garble), install, package operator bundle")
    group.add_argument("--release", action="store_true", help="Build and package full release tarball")
    group.add_argument("--uninstall", action="store_true", help="Remove installed files and completions")
    group.add_argument("--package-operator", action="store_true", help="Package existing install into operator kit")
    parser.add_argument("--dry-run", action="store_true", help="Print build and setup commands without executing them")
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    global IS_DRY_RUN
    if args.dry_run:
        IS_DRY_RUN = True
        os.environ["EMP3R0R_DRY_RUN"] = "1"

    core_dir = pathlib.Path(__file__).resolve().parent
    prefix = os.environ.get("PREFIX", "/usr/local")

    if args.uninstall:
        do_uninstall(prefix)
        return

    if args.package_operator:
        package_operator_bundle(prefix, core_dir)
        return

    mode = "--install"
    if args.release:
        mode = "--release"
    elif args.debug:
        mode = "--debug"
    elif args.build:
        mode = "--build"
    elif args.install_only:
        mode = "--install-only"

    with tempfile.TemporaryDirectory(prefix="emp3r0r-build-") as tmp_dir:
        temp_dir = pathlib.Path(tmp_dir)

        if mode == "--release":
            build(mode, temp_dir, core_dir)
            create_tar(core_dir, temp_dir)
        elif mode == "--build":
            build(mode, temp_dir, core_dir)
        elif mode == "--install-only":
            do_install(prefix, temp_dir, core_dir)
            package_operator_bundle(prefix, core_dir)
        elif mode in ("--install", "--debug"):
            build(mode, temp_dir, core_dir)
            prepare_misc_files(core_dir, temp_dir)
            do_install(prefix, temp_dir, core_dir)
            package_operator_bundle(prefix, core_dir)


if __name__ == "__main__":
    main()
