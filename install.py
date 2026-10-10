#!/usr/bin/env python3
from __future__ import annotations

"""
emp3r0r Installation & Operator Kit Script (Python)
---------------------------------------------------
Can be executed in two modes:
1. Repository Root Mode (building from source):
   Uses Docker (or Podman) as a throwaway build container to compile emp3r0r
   from the LOCAL source tree, installs the resulting binaries, and builds the
   operator kit plus a loadable operator container image
   (core/emp3r0r-operator-image.tar.zst).

2. Operator Kit Mode (installing on operator machine):
   Installs pre-compiled binaries into PREFIX (/usr/local), configures tmux,
   and installs Bash/Zsh shell completions.
"""

import argparse
import hashlib
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile

USE_COLOR = sys.stdout.isatty() and not os.environ.get("NO_COLOR")
IS_DRY_RUN = os.environ.get("EMP3R0R_DRY_RUN", "0").lower() in ("1", "true", "yes")

# Capabilities proxy-ns needs. They are NOT applied automatically (that would
# grant cap_sys_admin to a user-runnable binary); the installer only prints the
# opt-in setcap command.
PROXY_NS_CAPS = (
    "cap_sys_admin,cap_net_admin,cap_net_bind_service,cap_sys_chroot,cap_chown=ep"
)

# proxy-ns refuses to start without a config file at its compiled-in path; the
# kit ships the upstream default and the installer drops it here.
PROXY_NS_SYSTEM_CONFIG = pathlib.Path("/etc/proxy-ns/config.json")

# What each agent exclusion tag disables. Keep in sync with core/build.py and
# the //go:build constraints across core/.
AGENT_TAG_DOCS: dict[str, str] = {
    "no_mesh": "P2P mesh and memberlist gossip (peer discovery/routing)",
    "no_kcp": "KCP C2 transport and the xtaci kcp-go/kcptun/smux stack",
    "no_h2conn": "HTTP/2 duplex (h2conn) C2 channel",
    "no_utls": "uTLS TLS fingerprinting (falls back to crypto/tls)",
    "no_doh": "DNS-over-HTTPS resolver (uses the OS resolver)",
    "no_cdnproxy": "CDN fronting proxy (go-cdn2proxy)",
    "no_netlink": "netlink route/neighbour enumeration (procfs fallback)",
}

# Recommended --agent-slim exclusions. P2P mesh stays enabled; use the
# additional "no_mesh" tag to opt out. Keep in sync with core/build.py.
SLIM_AGENT_TAGS = "no_kcp no_h2conn no_utls no_doh no_cdnproxy no_netlink"


def agent_tag_reference() -> str:
    """Render the agent exclusion-tag reference for --help/--list-agent-tags."""
    width = max(len(tag) for tag in AGENT_TAG_DOCS)
    lines = ["Agent exclusion tags (combine freely with --agent-tags):"]
    for tag, desc in AGENT_TAG_DOCS.items():
        lines.append(f"  {tag:<{width}}  {desc}")
    lines.append("")
    lines.append(f"--agent-slim is shorthand for: {SLIM_AGENT_TAGS}")
    return "\n".join(lines)


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
            raise
        log_error(f"Command failed (exit code {e.returncode}): {cmd_str}")
        raise


def write_text_atomic(path: pathlib.Path, content: str) -> None:
    """Write a text file, force-overwriting whatever is already there.

    On Linux, truncating a file that is still mapped or held open (a sourced
    completion script, a previous installer still running, ...) fails with
    ETXTBSY/EBUSY ("Text file busy"). Writing a temp file in the same
    directory and renaming it over the target (os.replace) swaps the
    directory entry and never touches the busy inode, so the overwrite
    always succeeds.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_name(path.name + ".tmp")
    tmp_path.write_text(content, encoding="utf-8")
    os.replace(tmp_path, path)
    path.chmod(0o644)


def copy2_atomic(src: pathlib.Path, dst: pathlib.Path) -> None:
    """Copy a file, force-overwriting any existing file.

    On Linux, truncating a file that is still mapped/executed (e.g. a
    running emp3r0r-cc during a reinstall) fails with ETXTBSY/EBUSY
    ("Text file busy"). Copying to a temp file in the same directory and
    renaming it over the target (os.replace) never touches the busy inode,
    so reinstalling over a running binary works.
    """
    dst = pathlib.Path(dst)
    dst.parent.mkdir(parents=True, exist_ok=True)
    tmp = dst.with_name(dst.name + ".tmp")
    shutil.copy2(src, tmp)
    os.replace(tmp, dst)


# ===========================================================================
# Mode 1: Operator Kit Direct Installer
# ===========================================================================
def link_usr_local_bin(target: pathlib.Path) -> None:
    """Point /usr/local/bin/<name> at target (best effort)."""
    if not target.exists():
        return
    usr_local_bin = pathlib.Path("/usr/local/bin")
    usr_local_bin.mkdir(parents=True, exist_ok=True)
    symlink = usr_local_bin / target.name
    if symlink.is_symlink() or symlink.exists():
        symlink.unlink(missing_ok=True)
    try:
        symlink.symlink_to(target)
        log_info(f"Linked {target.name} to /usr/local/bin/{target.name}")
    except OSError as e:
        log_warn(f"Could not symlink /usr/local/bin/{target.name}: {e}")


def remove_obsolete_wireguard_config() -> None:
    """Remove the tmpfiles entry older installs used to create /var/run/wireguard.

    WireGuard now runs entirely in userspace (wireguard-go plus a gVisor
    netstack), so it needs neither a kernel TUN device nor the WireGuard socket
    directory; CAP_NET_ADMIN is only required by tun2socks, which creates a
    kernel TUN and installs routes. Deleting this emp3r0r-specific entry stops
    the host from recreating that directory on emp3r0r's behalf.
    /var/run/wireguard itself is left alone: it may belong to a real WireGuard
    installation.
    """
    stale = pathlib.Path("/etc/tmpfiles.d/emp3r0r-wireguard.conf")
    if IS_DRY_RUN:
        log_info(f"Would remove obsolete {stale}")
        return
    try:
        stale.unlink(missing_ok=True)
    except OSError as e:
        log_warn(f"Could not remove obsolete {stale}: {e}")


def do_operator_install(kit_dir: pathlib.Path, prefix_path: pathlib.Path) -> None:
    if (
        not IS_DRY_RUN
        and os.name != "nt"
        and hasattr(os, "geteuid")
        and os.geteuid() != 0
    ):
        log_info("Re-running with sudo...")
        sudo = ["sudo"]
        if sys.stdin is None or not sys.stdin.isatty():
            # Non-interactive: fail fast instead of blocking on a password prompt.
            sudo.append("-n")
        os.execvp(
            "sudo",
            sudo
            + [sys.executable, str(kit_dir / "install.py")]
            + sys.argv[1:],
        )

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
        copy2_atomic(kit_dir / "bin" / "emp3r0r", bin_dir / "emp3r0r")
        (bin_dir / "emp3r0r").chmod(0o755)

        if (kit_dir / "bin" / "emp3r0r-listener").exists():
            copy2_atomic(
                kit_dir / "bin" / "emp3r0r-listener", bin_dir / "emp3r0r-listener"
            )
            (bin_dir / "emp3r0r-listener").chmod(0o755)

        copy2_atomic(
            kit_dir / "lib" / "emp3r0r" / "emp3r0r-cc", data_dir / "emp3r0r-cc"
        )
        copy2_atomic(
            kit_dir / "lib" / "emp3r0r" / "emp3r0r-cat", data_dir / "emp3r0r-cat"
        )
        (data_dir / "emp3r0r-cc").chmod(0o755)
        (data_dir / "emp3r0r-cat").chmod(0o755)

        for d in ["build", "modules", "tmux", "zig", "nasm"]:
            src_d = kit_dir / "lib" / "emp3r0r" / d
            if src_d.is_dir():
                shutil.copytree(
                    src_d, data_dir / d, dirs_exist_ok=True, copy_function=copy2_atomic
                )
                log_info(f"Installed {d}")

        # zig is used as the C module cross compiler; point it at /usr/local/bin.
        link_usr_local_bin(data_dir / "zig" / "zig")
        # nasm assembles the Windows loader's SilentMoonwalk stub; expose the
        # kit-shipped copy as /usr/local/bin/nasm.
        link_usr_local_bin(data_dir / "nasm" / "nasm")

    donut_src = kit_dir / "lib" / "emp3r0r" / "bin" / "donut"
    if donut_src.is_file():
        log_info("Installing donut...")
        donut_dst = data_dir / "bin" / "donut"
        if not IS_DRY_RUN:
            donut_dst.parent.mkdir(parents=True, exist_ok=True)
            copy2_atomic(donut_src, donut_dst)
            donut_dst.chmod(0o755)
            link_usr_local_bin(donut_dst)
    else:
        log_warn("Donut not found in kit; skipping donut installation")

    proxy_ns_src = kit_dir / "lib" / "emp3r0r" / "bin" / "proxy-ns"
    proxy_ns_cfg_src = (
        kit_dir / "lib" / "emp3r0r" / "etc" / "proxy-ns" / "config.json"
    )
    if proxy_ns_src.is_file():
        log_info("Installing proxy-ns...")
        proxy_ns_dst = data_dir / "bin" / "proxy-ns"
        if not IS_DRY_RUN:
            proxy_ns_dst.parent.mkdir(parents=True, exist_ok=True)
            copy2_atomic(proxy_ns_src, proxy_ns_dst)
            proxy_ns_dst.chmod(0o755)
            link_usr_local_bin(proxy_ns_dst)
            # Install the default config only if the operator has none yet.
            if proxy_ns_cfg_src.is_file() and not PROXY_NS_SYSTEM_CONFIG.exists():
                PROXY_NS_SYSTEM_CONFIG.parent.mkdir(parents=True, exist_ok=True)
                copy2_atomic(proxy_ns_cfg_src, PROXY_NS_SYSTEM_CONFIG)
        log_info(
            "proxy-ns installed; run it with sudo, or grant the capabilities "
            "once to drop sudo:"
        )
        log_info(f"  sudo setcap {PROXY_NS_CAPS} {proxy_ns_dst}")
    else:
        log_warn("proxy-ns not found in kit; skipping proxy-ns installation")

    # tun2socks creates a kernel TUN device and installs routes, so emp3r0r-cc
    # needs CAP_NET_ADMIN to use it without root. WireGuard itself runs in
    # userspace and needs no privileges; the kernel-WireGuard socket directory
    # is obsolete and is cleaned up below. proxy-ns is deliberately left
    # uncapable: it needs several powerful capabilities, so operators run it
    # with sudo instead of granting them to a user-runnable binary.
    if shutil.which("setcap") or IS_DRY_RUN:
        log_info("Setting cap_net_admin on emp3r0r-cc (for tun2socks)...")
        run_cmd(
            ["setcap", "cap_net_admin=eip", str(data_dir / "emp3r0r-cc")], check=False
        )
    else:
        log_warn(
            "setcap not found; tun2socks will require running emp3r0r as root"
        )
    remove_obsolete_wireguard_config()

    cc_bin = data_dir / "emp3r0r-cc"
    # Refresh shell completions from the freshly installed binary. Writing the
    # output (not discarding it) keeps /etc/bash_completion.d/emp3r0r in sync
    # with the binary — otherwise operators keep a stale script that is missing
    # flags added in newer builds after upgrading.
    bash_comp_dir = pathlib.Path("/etc/bash_completion.d")
    if bash_comp_dir.is_dir():
        res = run_cmd(
            [str(cc_bin), "completion", "bash"], check=False, capture_output=True
        )
        if res.returncode == 0 and res.stdout:
            if not IS_DRY_RUN:
                try:
                    write_text_atomic(bash_comp_dir / "emp3r0r", res.stdout)
                except OSError as e:
                    # never fail the install because of a busy/locked file
                    log_warn(
                        f"Could not install Bash completion (overwrite failed: {e}); continuing"
                    )
                else:
                    log_info(
                        "Installed Bash completion to /etc/bash_completion.d/emp3r0r"
                    )
        else:
            log_warn("Failed to generate Bash completion script")

    log_success(f"emp3r0r operator kit installed successfully to {prefix_path}")
    log_info("Run 'emp3r0r client --help' to get started.")


# ===========================================================================
# Mode 2: Repository Container Build & Installation
# ===========================================================================
def find_container_engine() -> str | None:
    """Return the container engine on PATH without installing one."""
    if shutil.which("docker"):
        return "docker"
    if shutil.which("podman"):
        return "podman"
    return None


def detect_container_engine() -> str:
    engine = find_container_engine()
    if engine:
        log_info(f"Using container engine: {engine}")
        return engine

    log_warn(
        "Neither 'docker' nor 'podman' was found. Attempting to install 'podman'..."
    )
    if shutil.which("apt-get"):
        try:
            run_cmd(["sudo", "apt-get", "update", "-qq"])
            run_cmd(["sudo", "apt-get", "install", "-y", "podman"])
            engine = "podman"
        except (OSError, subprocess.CalledProcessError):
            log_error("Failed to install podman via apt-get")
    elif shutil.which("yum"):
        try:
            run_cmd(["sudo", "yum", "install", "-y", "podman"])
            engine = "podman"
        except (OSError, subprocess.CalledProcessError):
            log_error("Failed to install podman via yum")
    else:
        log_error(
            "Neither 'docker' nor 'podman' was found, and apt-get/yum is not available to install podman. "
            "Please install docker or podman manually."
        )
    log_info(f"Using container engine: {engine}")
    return engine


def needs_selinux_relabel() -> bool:
    """Return True when bind mounts must be relabeled for SELinux.

    The kernel exposes /sys/fs/selinux only while SELinux is enabled
    (enforcing or permissive). On such hosts a bind mount keeps its host
    label and the container is denied access to /src unless the engine
    relabels it.
    """
    return pathlib.Path("/sys/fs/selinux/enforce").exists()


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
            except (OSError, subprocess.CalledProcessError):
                log_error(f"Failed to install host tools: {' '.join(missing)}")
        elif shutil.which("yum"):
            try:
                run_cmd(["sudo", "yum", "install", "-y"] + missing)
            except (OSError, subprocess.CalledProcessError):
                log_error(f"Failed to install host tools via yum: {' '.join(missing)}")
        else:
            log_error(
                f"Missing host tools: {' '.join(missing)}. Please install them manually."
            )

    build_py = repo_root / "core" / "build.py"
    if not build_py.exists():
        log_error(
            f"core/build.py not found under {repo_root}. Run install.py from the emp3r0r repo root."
        )


def builder_image_ref(repo_root: pathlib.Path) -> str:
    """Return the builder image reference pinned to the current Dockerfile.

    The tag carries a hash of the Dockerfile so changing the recipe (a new
    pinned toolchain, a new mingw shim, donut/proxy-ns, ...) rebuilds the image
    instead of silently reusing a stale ``emp3r0r-builder``. Without this, an
    old image keeps producing kits that are missing every tool added since it
    was built -- which is exactly how donut and proxy-ns went missing while the
    image still existed.
    """
    dockerfile = repo_root / "Dockerfile"
    if not dockerfile.is_file():
        return "emp3r0r-builder"
    try:
        digest = hashlib.sha256(dockerfile.read_bytes()).hexdigest()[:12]
    except OSError as e:
        log_warn(
            f"Could not hash {dockerfile}: {e}; using the unversioned builder tag"
        )
        return "emp3r0r-builder"
    return f"emp3r0r-builder:{digest}"


def docker_build(
    container_engine: str,
    repo_root: pathlib.Path,
    build_arg: str,
    disable_garble: bool,
    extra_build_flags: str = "",
) -> None:
    log_info(f"Using local source: {repo_root}")

    builder_image = builder_image_ref(repo_root)

    inspect_res = run_cmd(
        [container_engine, "image", "inspect", builder_image],
        check=False,
        capture_output=True,
    )

    if inspect_res.returncode != 0 and not IS_DRY_RUN:
        log_info(
            f"Builder image '{builder_image}' not found. Building it from Dockerfile..."
        )
        dockerfile = repo_root / "Dockerfile"
        res = run_cmd(
            [
                container_engine,
                "build",
                "-t",
                builder_image,
                "-f",
                str(dockerfile),
                str(repo_root),
            ],
            check=False,
        )
        if res.returncode != 0:
            log_error(f"Failed to build builder image '{builder_image}'")
    else:
        log_info(f"Using builder image '{builder_image}'")

    log_info(
        f"Starting Docker build container ({builder_image}) to compile emp3r0r and modules..."
    )

    build_env = []
    if disable_garble or os.environ.get("EMP3R0R_DISABLE_GARBLE") == "1":
        build_env.extend(["-e", "EMP3R0R_DISABLE_GARBLE=1"])

    if IS_DRY_RUN:
        build_env.extend(["-e", "EMP3R0R_DRY_RUN=1"])
        build_arg += " --dry-run"

    # Append any extra target/feature flags (--lightweight / --targets /
    # --agent-slim / --agent-tags ...).
    full_build_arg = build_arg
    if extra_build_flags:
        full_build_arg = f"{build_arg} {extra_build_flags}"

    build_env.extend(["-e", f"EMP3R0R_BUILD_ARG={full_build_arg}"])

    container_cmd = (
        "set -euo pipefail\n"
        "export PREFIX=/usr/local\n"
        "export GOPATH=/root/go\n"
        "export PYTHONUNBUFFERED=1\n"
        "PYTHON_BIN=$(command -v python3 || command -v python3.12 || command -v python3.11 || command -v python3.10 || find /usr/local/bin /usr/bin -name 'python3*' 2>/dev/null | head -n 1)\n"
        'if [ -z "$PYTHON_BIN" ]; then\n'
        "  echo '[ERROR] Python 3 binary not found in builder container.' >&2\n"
        "  exit 1\n"
        "fi\n"
        "cd /src/core\n"
        '  "$PYTHON_BIN" build.py ${EMP3R0R_BUILD_ARG:---install}\n'
        'echo "Build complete."\n'
    )

    # ':z' asks the engine to relabel the source tree as shared container
    # content; without it SELinux hosts get "permission denied" on /src.
    mount_opts = ""
    if needs_selinux_relabel():
        mount_opts = ":z"
        log_info("SELinux detected; relabeling the bind mount (:z)")

    run_args = [
        container_engine,
        "run",
        "--rm",
        "-v",
        f"{repo_root}:/src{mount_opts}",
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


def export_operator_image(
    container_engine: str, kit_dir: pathlib.Path, core_dir: pathlib.Path
) -> None:
    """Build the operator container image and export it for transfer.

    The kit is C2-specific -- its agent stubs and modules carry this server's
    MagicString -- so a published image cannot be reused across servers. The
    build host therefore builds the image from its own kit and saves a tarball
    the operator machine can `docker load`.

    The image is only ever tagged `latest`; there is no release version to pin,
    and operators can tag the imported image however they like.
    """
    image = "emp3r0r-operator:latest"

    log_info(f"Building operator container image {image}...")
    res = run_cmd([container_engine, "build", "-t", image, str(kit_dir)], check=False)
    if res.returncode != 0:
        log_warn("Operator image build failed; see OPERATOR.md to build it manually")
        return

    out = core_dir / "emp3r0r-operator-image.tar.zst"
    tar_path = core_dir / "emp3r0r-operator-image.tar"
    log_info(f"Exporting {image} to {out} (this can take a few minutes)...")
    res = run_cmd(
        [container_engine, "save", "-o", str(tar_path), image], check=False
    )
    if res.returncode != 0 or IS_DRY_RUN:
        if not IS_DRY_RUN:
            log_warn("Operator image export failed")
        tar_path.unlink(missing_ok=True)
        return

    # zstd -T0 keeps the export fast for the multi-GB image; modern Docker can
    # `load` a zstd-compressed tarball directly.
    res = run_cmd(
        ["zstd", "-T0", "-3", "-f", str(tar_path), "-o", str(out)], check=False
    )
    tar_path.unlink(missing_ok=True)
    if res.returncode != 0:
        log_warn("Operator image compression failed")
        return

    log_success(f"Operator container image saved to {out}")
    log_info(f"Copy it to the operator machine, then: docker load -i {out.name}")


def install_from_operator_kit(
    cached_kit: pathlib.Path,
    prefix: str,
    core_dir: pathlib.Path,
    container_engine: str | None = None,
    build_image: bool = False,
) -> None:
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

        # Build/export the image before the local install: it needs no root, so
        # a non-root build host still gets the container without a sudo prompt.
        if build_image and container_engine:
            export_operator_image(container_engine, kit_dir, core_dir)

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
        if res.returncode != 0:
            log_warn("Operator kit installer reported an error")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="emp3r0r Installation and Operator Kit Installer Script",
        epilog=agent_tag_reference(),
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
        "--no-operator-image",
        action="store_true",
        help="Do not build/export the operator container image",
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

    # ── Target selection (forwarded verbatim to core/build.py) ───────────────
    tgt_group = parser.add_argument_group(
        "target selection",
        "Restrict which agent stubs/shared-objects are compiled inside the "
        "build container. C2 binaries (cc, cat, listener) are always built. "
        "These flags are forwarded verbatim to core/build.py.",
    )
    tgt_excl = tgt_group.add_mutually_exclusive_group()
    tgt_excl.add_argument(
        "--lightweight",
        action="store_true",
        default=False,
        help=(
            "Build only linux/amd64 and windows/amd64 exe/dll targets. "
            "Fastest preset — ideal for development or x86-64-only deployments."
        ),
    )
    tgt_excl.add_argument(
        "--targets",
        metavar="OS/ARCH[,OS/ARCH,...]",
        default="",
        help=(
            "Comma-separated list of OS/arch targets, e.g. "
            "'linux/amd64,windows/amd64,windows/386'."
        ),
    )

    # ── Agent feature selection (forwarded verbatim to core/build.py) ────────
    feat_group = parser.add_argument_group(
        "agent feature selection",
        "Control which optional agent subsystems are compiled into the agent "
        "payloads. C2 binaries (cc, cat, listener) always keep every feature. "
        "These flags are forwarded verbatim to core/build.py.",
    )
    feat_group.add_argument(
        "--agent-slim",
        action="store_true",
        default=False,
        help=(
            "Compile agents without the optional transports/features (KCP, "
            "h2conn, uTLS, DoH, CDN proxy, netlink) while keeping the core "
            "P2P mesh (mTLS/SMB) enabled. Add the 'no_mesh' tag to opt out "
            "of P2P entirely."
        ),
    )
    feat_group.add_argument(
        "--agent-tags",
        metavar="TAGS",
        default="",
        help=(
            "Space-separated Go build tags to add to every agent payload, e.g. "
            "'no_mesh no_kcp' or a custom tag. Combined with --agent-slim when "
            "both are given. See the tag reference below or --list-agent-tags."
        ),
    )
    parser.add_argument(
        "--list-agent-tags",
        action="store_true",
        help="Print the available agent exclusion tags and exit",
    )

    return parser.parse_args()


def collect_extra_build_flags(args: argparse.Namespace) -> str:
    """Translate install.py options into core/build.py arguments.

    The result is embedded in ``EMP3R0R_BUILD_ARG`` and expanded by the builder
    container's shell, so values containing spaces are quoted here to keep them
    as a single argument.
    """
    flags = []
    if getattr(args, "lightweight", False):
        flags.append("--lightweight")
    elif getattr(args, "targets", ""):
        # Shell-quote so the comma-separated value survives the env var.
        flags.append(f"--targets {args.targets}")
    if getattr(args, "agent_slim", False):
        flags.append("--agent-slim")
    agent_tags = getattr(args, "agent_tags", "").strip()
    if agent_tags:
        # Quote the tag set so word-splitting yields one flag with many tags
        # when the build container expands EMP3R0R_BUILD_ARG.
        flags.append(f'--agent-tags "{agent_tags}"')
    return " ".join(flags)


def main() -> None:
    args = parse_args()

    if getattr(args, "list_agent_tags", False):
        print(agent_tag_reference())
        return

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

    # Build any extra target/feature flags to pass into core/build.py.
    extra_build_flags = collect_extra_build_flags(args)

    build_image = not args.no_operator_image

    if args.skip_build:
        log_info("--skip-build: skipping Docker build, using cached operator kit")
        check_host_deps(script_dir)
        engine = find_container_engine() if build_image else None
        if build_image and engine is None:
            log_warn("Docker/Podman not found; skipping the operator image build")
        install_from_operator_kit(
            cached_kit,
            args.prefix,
            script_dir / "core",
            engine,
            build_image and engine is not None,
        )
    else:
        container_engine = detect_container_engine()
        check_host_deps(script_dir)
        log_info("Starting emp3r0r installation (Docker-based build from local source)")
        docker_build(
            container_engine, script_dir, build_arg, disable_garble, extra_build_flags
        )
        install_from_operator_kit(
            cached_kit, args.prefix, script_dir / "core", container_engine, build_image
        )

    log_success(f"emp3r0r installed successfully to {args.prefix}")


if __name__ == "__main__":
    main()
