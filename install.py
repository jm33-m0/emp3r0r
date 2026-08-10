#!/usr/bin/env python3
from __future__ import annotations

"""
emp3r0r Installation & Operator Kit Script (Python)
---------------------------------------------------
Can be executed in two modes:
1. Repository Root Mode (building from source):
   Uses Docker (or Podman) as a throwaway build container to compile emp3r0r
   from the LOCAL source tree, then installs the resulting binaries.

2. Operator Kit Mode (installing on operator machine):
   Installs pre-compiled binaries into PREFIX (/usr/local), sets WireGuard
   capabilities, configures tmux, and installs Bash/Zsh shell completions.
"""

import argparse
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import time

DONUT_URL = "https://github.com/TheWover/donut/releases/download/v1.1/donut_v1.1.tar.gz"
DONUT_ARCHIVE_NAME = "donut_v1.1.tar.gz"

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
    cmd: list[str],
    check: bool = True,
    cwd: pathlib.Path | str | None = None,
    env: dict[str, str] | None = None,
    capture_output: bool = False,
    text: bool = True,
) -> subprocess.CompletedProcess:
    cmd_str = " ".join(cmd)
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
        )
    except subprocess.CalledProcessError as e:
        if not check:
            raise e
        log_error(f"Command failed (exit code {e.returncode}): {cmd_str}")
        raise e


# ===========================================================================
# Mode 1: Operator Kit Direct Installer
# ===========================================================================
def do_operator_install(kit_dir: pathlib.Path, prefix_path: pathlib.Path) -> None:
    if not IS_DRY_RUN and os.name != "nt" and hasattr(os, "geteuid") and os.geteuid() != 0:
        log_info("Re-running with sudo...")
        os.execvp("sudo", ["sudo", sys.executable, str(kit_dir / "install.py")] + sys.argv[1:])

    bin_dir = prefix_path / "bin"
    data_dir = prefix_path / "lib" / "emp3r0r"
    install_user = os.environ.get("SUDO_USER") or os.environ.get("USER") or "root"

    log_info(f"Installing emp3r0r operator kit to {prefix_path}")
    log_info(f"Operator user: {install_user}")

    for req in [
        kit_dir / "bin" / "emp3r0r",
        kit_dir / "lib" / "emp3r0r" / "emp3r0r-cc",
        kit_dir / "lib" / "emp3r0r" / "emp3r0r-cat",
    ]:
        if not req.exists() and not IS_DRY_RUN:
            log_error(f"Kit is missing required file: {req.relative_to(kit_dir)}")

    for dep in ["setcap", "tmux"]:
        if not shutil.which(dep):
            log_warn(f"Required tool '{dep}' not found. Attempting to install...")
            if shutil.which("apt-get"):
                pkg = "libcap2-bin" if dep == "setcap" else dep
                run_cmd(["apt-get", "update", "-qq"], check=False)
                run_cmd(["apt-get", "install", "-y", pkg], check=False)
            elif shutil.which("yum"):
                pkg = "libcap" if dep == "setcap" else dep
                run_cmd(["yum", "install", "-y", pkg], check=False)
            else:
                log_warn(f"{dep} is required but could not be installed automatically.")

    if shutil.which("tmux") or IS_DRY_RUN:
        res = run_cmd(["tmux", "has-session", "-t", "emp3r0r"], check=False)
        if res.returncode == 0 or IS_DRY_RUN:
            log_warn("Stopping existing emp3r0r tmux session...")
            run_cmd(["tmux", "kill-session", "-t", "emp3r0r"], check=False)

    log_info("Creating directories...")
    if not IS_DRY_RUN:
        bin_dir.mkdir(parents=True, exist_ok=True)
        (data_dir / "build").mkdir(parents=True, exist_ok=True)

    log_info("Installing binaries and data...")
    if not IS_DRY_RUN:
        shutil.copy2(kit_dir / "bin" / "emp3r0r", bin_dir / "emp3r0r")
        (bin_dir / "emp3r0r").chmod(0o755)

        if (kit_dir / "bin" / "emp3r0r-listener").exists():
            shutil.copy2(kit_dir / "bin" / "emp3r0r-listener", bin_dir / "emp3r0r-listener")
            (bin_dir / "emp3r0r-listener").chmod(0o755)

        shutil.copy2(kit_dir / "lib" / "emp3r0r" / "emp3r0r-cc", data_dir / "emp3r0r-cc")
        shutil.copy2(kit_dir / "lib" / "emp3r0r" / "emp3r0r-cat", data_dir / "emp3r0r-cat")
        (data_dir / "emp3r0r-cc").chmod(0o755)
        (data_dir / "emp3r0r-cat").chmod(0o755)

        for d in ["build", "modules", "tmux"]:
            src_d = kit_dir / "lib" / "emp3r0r" / d
            if src_d.is_dir():
                shutil.copytree(src_d, data_dir / d, dirs_exist_ok=True)
                log_info(f"Installed {d}")

    if shutil.which("setcap") or IS_DRY_RUN:
        log_info("Setting cap_net_admin on emp3r0r-cc...")
        run_cmd(["setcap", "cap_net_admin=eip", str(data_dir / "emp3r0r-cc")], check=False)

    log_info("Creating /var/run/wireguard...")
    wg_dir = pathlib.Path("/var/run/wireguard")
    if not IS_DRY_RUN:
        try:
            wg_dir.mkdir(parents=True, exist_ok=True)
            wg_dir.chmod(0o755)
            shutil.chown(wg_dir, user=install_user, group=install_user)
        except Exception:
            pass

    cc_bin = data_dir / "emp3r0r-cc"
    run_cmd([str(cc_bin), "completion", "bash"], check=False, capture_output=True)

    log_success(f"emp3r0r operator kit installed successfully to {prefix_path}")
    log_info("Run 'emp3r0r client --help' to get started.")


# ===========================================================================
# Mode 2: Repository Container Build & Installation
# ===========================================================================
def detect_container_engine() -> str:
    if shutil.which("docker"):
        engine = "docker"
    elif shutil.which("podman"):
        engine = "podman"
    else:
        log_warn("Neither 'docker' nor 'podman' was found. Attempting to install 'podman'...")
        if shutil.which("apt-get"):
            try:
                run_cmd(["sudo", "apt-get", "update", "-qq"])
                run_cmd(["sudo", "apt-get", "install", "-y", "podman"])
                engine = "podman"
            except Exception:
                log_error("Failed to install podman via apt-get")
        elif shutil.which("yum"):
            try:
                run_cmd(["sudo", "yum", "install", "-y", "podman"])
                engine = "podman"
            except Exception:
                log_error("Failed to install podman via yum")
        else:
            log_error(
                "Neither 'docker' nor 'podman' was found, and apt-get/yum is not available to install podman. "
                "Please install docker or podman manually."
            )
    log_info(f"Using container engine: {engine}")
    return engine


def check_host_deps(repo_root: pathlib.Path) -> None:
    missing = []
    for tool in ["tar", "zstd"]:
        if not shutil.which(tool):
            missing.append(tool)

    if missing:
        log_warn(f"Missing host tools: {' '.join(missing)}. Installing...")
        if shutil.which("apt-get"):
            try:
                run_cmd(["sudo", "apt-get", "update", "-qq"])
                run_cmd(["sudo", "apt-get", "install", "-y"] + missing)
            except Exception:
                log_error(f"Failed to install host tools: {' '.join(missing)}")
        elif shutil.which("yum"):
            try:
                run_cmd(["sudo", "yum", "install", "-y"] + missing)
            except Exception:
                log_error(f"Failed to install host tools via yum: {' '.join(missing)}")
        else:
            log_error(f"Missing host tools: {' '.join(missing)}. Please install them manually.")

    build_py = repo_root / "core" / "build.py"
    if not build_py.exists():
        log_error(f"core/build.py not found under {repo_root}. Run install.py from the emp3r0r repo root.")


def docker_build(
    container_engine: str,
    repo_root: pathlib.Path,
    build_arg: str,
    disable_garble: bool,
) -> None:
    log_info(f"Using local source: {repo_root}")

    builder_image = "emp3r0r-builder"

    inspect_res = run_cmd(
        [container_engine, "image", "inspect", builder_image],
        check=False,
        capture_output=True,
    )

    if inspect_res.returncode != 0 and not IS_DRY_RUN:
        log_info(f"Builder image '{builder_image}' not found. Building it from Dockerfile...")
        dockerfile = repo_root / "Dockerfile"
        res = run_cmd(
            [container_engine, "build", "-t", builder_image, "-f", str(dockerfile), str(repo_root)],
            check=False,
        )
        if res.returncode != 0:
            log_error(f"Failed to build builder image '{builder_image}'")
    else:
        log_info(f"Using builder image '{builder_image}'")

    log_info(f"Starting Docker build container ({builder_image}) to compile emp3r0r and modules...")

    build_env = []
    if disable_garble or os.environ.get("EMP3R0R_DISABLE_GARBLE") == "1":
        build_env.extend(["-e", "EMP3R0R_DISABLE_GARBLE=1"])

    if IS_DRY_RUN:
        build_env.extend(["-e", "EMP3R0R_DRY_RUN=1"])
        build_arg += " --dry-run"

    build_env.extend(["-e", f"EMP3R0R_BUILD_ARG={build_arg}"])

    container_cmd = (
        "set -euo pipefail\n"
        "export PREFIX=/usr/local\n"
        "export GOPATH=/root/go\n"
        "export PYTHONUNBUFFERED=1\n"
        "PYTHON_BIN=$(command -v python3 || command -v python3.12 || command -v python3.11 || command -v python3.10 || find /usr/local/bin /usr/bin -name 'python3*' 2>/dev/null | head -n 1)\n"
        "if [ -z \"$PYTHON_BIN\" ]; then\n"
        "  echo '[ERROR] Python 3 binary not found in builder container.' >&2\n"
        "  exit 1\n"
        "fi\n"
        "cd /src/core\n"
        '  "$PYTHON_BIN" build.py ${EMP3R0R_BUILD_ARG:---install}\n'
        'echo "Build complete."\n'
    )

    run_args = [
        container_engine,
        "run",
        "--rm",
        "-v",
        f"{repo_root}:/src",
        *build_env,
        builder_image,
        "/bin/bash",
        "-c",
        container_cmd,
    ]

    res = run_cmd(run_args, check=False)
    if res.returncode != 0 and not IS_DRY_RUN:
        log_error("Docker build failed")

    log_success("Docker build completed")


def install_from_operator_kit(cached_kit: pathlib.Path, prefix: str) -> None:
    if not cached_kit.exists() and not IS_DRY_RUN:
        log_error(f"Operator kit not found: {cached_kit}")

    with tempfile.TemporaryDirectory(prefix="emp3r0r-kit-extract-") as tmp_dir:
        tmp_path = pathlib.Path(tmp_dir)
        log_info("Extracting operator kit to install...")
        res = run_cmd(
            ["tar", "-I", "zstd", "-xpf", str(cached_kit), "-C", str(tmp_path)],
            check=False,
        )

        kit_dir = tmp_path / "emp3r0r-operator-kit"
        installer_py = kit_dir / "install.py"
        log_info("Running operator kit installer...")
        env = os.environ.copy()
        env["PREFIX"] = prefix
        if IS_DRY_RUN:
            env["EMP3R0R_DRY_RUN"] = "1"

        cmd = [sys.executable, str(installer_py)]
        if IS_DRY_RUN:
            cmd.append("--dry-run")

        res = run_cmd(cmd, env=env, check=False)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="emp3r0r Installation and Operator Kit Installer Script",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Build with debug symbols (no garble obfuscation)",
    )
    parser.add_argument(
        "--disable-garble",
        action="store_true",
        help="Release build without garble obfuscation",
    )
    parser.add_argument(
        "--prefix",
        default="/usr/local",
        help="Install prefix (default: /usr/local)",
    )
    parser.add_argument(
        "--skip-build",
        action="store_true",
        help="Skip Docker build; reinstall from the last cached build",
    )
    parser.add_argument(
        "--operator-kit",
        action="store_true",
        help="Run operator kit installation directly",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print build and setup commands without executing them",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    global IS_DRY_RUN
    if args.dry_run:
        IS_DRY_RUN = True
        os.environ["EMP3R0R_DRY_RUN"] = "1"

    script_dir = pathlib.Path(__file__).resolve().parent
    prefix_path = pathlib.Path(os.environ.get("PREFIX", args.prefix))

    # Detect if running directly inside an extracted operator kit
    is_kit_dir = (script_dir / "lib" / "emp3r0r" / "emp3r0r-cc").is_file()

    if args.operator_kit or is_kit_dir:
        do_operator_install(script_dir, prefix_path)
        return

    cached_kit = script_dir / "core" / "emp3r0r-operator-kit.tar.zst"

    build_arg = "--install"
    if args.debug:
        build_arg = "--debug"

    disable_garble = args.disable_garble
    if disable_garble:
        os.environ["EMP3R0R_DISABLE_GARBLE"] = "1"

    if args.skip_build:
        log_info("--skip-build: skipping Docker build, using cached operator kit")
        check_host_deps(script_dir)
        install_from_operator_kit(cached_kit, args.prefix)
    else:
        container_engine = detect_container_engine()
        check_host_deps(script_dir)
        log_info("Starting emp3r0r installation (Docker-based build from local source)")
        docker_build(container_engine, script_dir, build_arg, disable_garble)
        install_from_operator_kit(cached_kit, args.prefix)

    log_success(f"emp3r0r installed successfully to {args.prefix}")


if __name__ == "__main__":
    main()
