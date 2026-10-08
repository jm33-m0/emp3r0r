#!/usr/bin/env python3
from __future__ import annotations

"""
emp3r0r Core Build and Installation Script (Python)
---------------------------------------------------
Builds C2 server binaries (CC, cat, listener), agent stubs (pure Go & CGO),
shared objects, BOFs, and custom modules. Performs local system installation,
operator bundle packaging, and uninstallation.

Usage:
  python3 build.py [COMMAND] [OPTIONS]

Commands:
  --build             Build binaries and agent stubs in temp directory
  --install           Build binaries, install to system prefix, package operator bundle
  --install-only      Skip build; install pre-built binaries and package operator bundle
  --debug             Build with debug mode (no garble), install, package operator bundle
  --release           Build and package full release tarball (emp3r0r.tar.zst)
  --uninstall         Remove installed files and completions from install prefix
  --package-operator  Package existing installed files into emp3r0r-operator-kit.tar.zst
  --build-payload     Build exactly one agent payload (see single payload options)

Single payload options (only with --build-payload):
  --payload-kind TYPE     shared (c-shared object), cgo (cgo exe), or pure (pure Go exe)
  --payload-os OS         linux or windows (default: linux)
  --payload-arch ARCH     target arch (default: amd64)
  --payload-output PATH   output file path (required)
  --payload-debug         build without garble/stripping
  --payload-magic-string S
                          MagicString to embed so the payload interoperates
                          with an already-built C2 (random when omitted)

Target selection options (combinable with any build command):
  --lightweight       Build only linux/amd64 and windows/amd64 exe/dll targets.
                      Much faster than a full build; ideal for development and
                      quick deployments that only need x86-64 coverage.
  --targets OS/ARCH[,OS/ARCH,...]
                      Comma-separated list of exact OS/arch targets to build.
                      Examples:
                        --targets linux/amd64
                        --targets linux/amd64,windows/amd64,windows/386
                      Recognised OS values : linux, windows
                      Recognised arch values: amd64, 386, arm, arm64, mips,
                                              mips64, riscv64, ppc64
                      The special token "shared" selects all shared-object
                      (.so/.dll) variants for the matched targets.
                      C2 server binaries (cc, cat, listener) are always built.

Agent feature selection options (combinable with any build command):
  --agent-slim        Compile agent payloads without the optional transports
                      and features (KCP, h2conn, uTLS, DoH, CDN proxy, netlink)
                      while keeping the core P2P mesh (mTLS/SMB) enabled. Add
                      the ``no_mesh`` tag to opt out of P2P entirely.
  --agent-tags TAGS   Extra Go build tags for every agent payload, e.g.
                      "no_mesh no_kcp" or a custom tag. Combined with
                      --agent-slim when both are given. C2 server binaries are
                      always built with the full feature set.

Environment variables:
  EMP3R0R_DISABLE_GARBLE=1   Disable garble obfuscation for non-debug builds
  PREFIX=/usr/local          Custom install prefix
  EMP3R0R_TARGETS            Comma-separated targets (same format as --targets)
  EMP3R0R_LIGHTWEIGHT=1      Equivalent to --lightweight
  EMP3R0R_SLIM_AGENT=1       Equivalent to --agent-slim
  EMP3R0R_AGENT_TAGS         Extra Go build tags for agent payloads
"""

import argparse
import hashlib
import os
import pathlib
import platform
import re
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.request

DONUT_URL = "https://github.com/TheWover/donut/releases/download/v1.1/donut_v1.1.tar.gz"
DONUT_ARCHIVE_NAME = "donut_v1.1.tar.gz"
# Crystal Palace (the Crystal-Kit module's crystal_pack linker). The
# distribution directory is gitignored, so the build installs it. The URL is a
# moving "latest" alias, so the pinned digest must be refreshed when upstream
# cuts a new release; the build fails closed rather than extracting an
# unverified archive.
CRYSTALPALACE_URL = "https://tradecraftgarden.org/download/cpdist-latest.tgz"
CRYSTALPALACE_ARCHIVE_NAME = "cpdist-latest.tgz"
CRYSTALPALACE_SHA256 = (
    "39af4ad53d612b0a2c9c3948ef97d9de3a2fc4730012a54e2bab7f081d5d4e32"
)
REQUIRED_GO_VERSION = "1.26.2"
REQUIRED_ZIG_VERSION = "0.16.0"
# zig is the explicit cross compiler for the Windows loader (and backs the
# mingw shims in the builder image), so the build host needs it too. The
# release is pinned per host platform and SHA-256 verified before extraction;
# builds never consume an unverified toolchain.
ZIG_URL_TEMPLATE = "https://ziglang.org/download/{v}/zig-{zig_platform}-{v}.tar.xz"
ZIG_SHA256 = {
    "x86_64-linux": (
        "70e49664a74374b48b51e6f3fdfbf437f6395d42509050588bd49abe52ba3d00"
    ),
    "aarch64-linux": (
        "ea4b09bfb22ec6f6c6ceac57ab63efb6b46e17ab08d21f69f3a48b38e1534f17"
    ),
    "x86_64-macos": (
        "0387557ed1877bc6a2e1802c8391953baddba76081876301c522f52977b52ba7"
    ),
    "aarch64-macos": (
        "b23d70deaa879b5c2d486ed3316f7eaa53e84acf6fc9cc747de152450d401489"
    ),
}
REQUIRED_FREE_KB = 10 * 1024 * 1024  # 10 GB

# Optional agent features that can be compiled out. The full build keeps them
# all (no tags); --agent-slim drops the optional transports and features while
# keeping the core P2P mesh (memberlist gossip + mTLS/SMB relay) enabled. Use
# the additional ``no_mesh`` tag to opt out of P2P entirely. The tag names must
# stay in sync with the //go:build constraints across core/.
SLIM_AGENT_TAGS = "no_kcp no_h2conn no_utls no_doh no_cdnproxy no_netlink"

# What each exclusion tag disables, shown in --help and --list-agent-tags.
# Keep in sync with core/ build constraints and with install.py.
AGENT_TAG_DOCS: dict[str, str] = {
    "no_mesh": "P2P mesh and memberlist gossip (peer discovery/routing)",
    "no_kcp": "KCP C2 transport and the xtaci kcp-go/kcptun/smux stack",
    "no_h2conn": "HTTP/2 duplex (h2conn) C2 channel",
    "no_utls": "uTLS TLS fingerprinting (falls back to crypto/tls)",
    "no_doh": "DNS-over-HTTPS resolver (uses the OS resolver)",
    "no_cdnproxy": "CDN fronting proxy (go-cdn2proxy)",
    "no_netlink": "netlink route/neighbour enumeration (procfs fallback)",
}


def agent_tag_reference() -> str:
    """Render the agent exclusion-tag reference for --help/--list-agent-tags."""
    width = max(len(tag) for tag in AGENT_TAG_DOCS)
    lines = ["Agent exclusion tags (combine freely with --agent-tags):"]
    for tag, desc in AGENT_TAG_DOCS.items():
        lines.append(f"  {tag:<{width}}  {desc}")
    lines.append("")
    lines.append(f"--agent-slim is shorthand for: {SLIM_AGENT_TAGS}")
    return "\n".join(lines)

# Extra Go build tags applied to every agent payload in the current run. Set
# once by build()/build_single_payload() from the CLI and environment so the
# per-artefact helpers stay focused on their own toolchain concerns.
AGENT_EXTRA_TAGS = ""

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


def verify_sha256(path: pathlib.Path, expected: str) -> bool:
    """Return True when path's SHA-256 matches expected (case-insensitive)."""
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            digest.update(chunk)
    actual = digest.hexdigest()
    if actual.lower() != expected.lower():
        log_warn(f"Checksum mismatch for {path}: got {actual}, want {expected}")
        return False
    return True


# The origin (Cloudflare) rejects the stdlib default Python-urllib/x.y UA with
# 403, so present a browser UA.
DOWNLOAD_USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)


def download_file(url: str, dest: pathlib.Path, sha256: str | None = None) -> bool:
    """Download url to dest using urllib only.

    When sha256 is set the archive is verified and a mismatch deletes it and
    fails closed, so callers never consume an unverified download.
    """
    request = urllib.request.Request(
        url, headers={"User-Agent": DOWNLOAD_USER_AGENT}
    )
    try:
        log_info(f"Downloading {url} to {dest}...")
        with urllib.request.urlopen(request, timeout=60) as response:
            with open(dest, "wb") as f:
                shutil.copyfileobj(response, f)
    except Exception as e:
        log_warn(f"Failed to download {url}: {e}")
        dest.unlink(missing_ok=True)
        return False
    if sha256 is not None and not verify_sha256(dest, sha256):
        dest.unlink(missing_ok=True)
        return False
    return True


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


def get_git_version() -> str:
    env_tag = os.environ.get("TAG")
    if env_tag:
        return env_tag
    res = run_cmd(
        ["git", "describe", "--tags", "--always"], check=False, capture_output=True
    )
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
    official_go = goroot / "bin" / "go"
    gopath = pathlib.Path(os.environ.get("GOPATH", pathlib.Path.home() / "go"))

    # Only pin GOROOT when the canonical /usr/local/go is a real toolchain.
    # Hosts where Go lives elsewhere (e.g. actions/setup-go under
    # /opt/hostedtoolcache) would otherwise export a nonexistent GOROOT and
    # every subsequent go invocation would fail; respect the toolchain's own
    # GOROOT in that case.
    if official_go.is_file() and os.access(official_go, os.X_OK):
        os.environ["GOROOT"] = str(goroot)
        actual_go = str(official_go)
    else:
        actual_go = go_bin
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


def zig_platform() -> str | None:
    """Return zig's release platform tag for this host (e.g. x86_64-linux)."""
    os_name = {"linux": "linux", "darwin": "macos"}.get(platform.system().lower())
    arch = {
        "x86_64": "x86_64",
        "amd64": "x86_64",
        "aarch64": "aarch64",
        "arm64": "aarch64",
    }.get(platform.machine().lower())
    if os_name and arch:
        return f"{arch}-{os_name}"
    return None


def install_zig(target_dir: pathlib.Path | None = None) -> pathlib.Path | None:
    """Install the pinned zig toolchain under ``target_dir/zig``.

    ``zig cc`` is the explicit cross compiler for the Windows loader, so zig is
    installed next to emp3r0r (and copied into the operator kit). With no
    explicit ``target_dir`` an existing zig on PATH is accepted; otherwise the
    toolchain lands in ``<prefix>/lib/emp3r0r``. The archive is SHA-256
    verified before extraction and ``/usr/local/bin/zig`` points at the
    installed binary. Returns the executable path, or None on failure.
    """
    if target_dir is None:
        existing = shutil.which("zig")
        if existing:
            log_info(f"zig is already installed: {existing}")
            return pathlib.Path(existing)
        target_dir = (
            pathlib.Path(os.environ.get("PREFIX", "/usr/local")) / "lib" / "emp3r0r"
        )
    zig_dir = target_dir / "zig"
    zig_bin = zig_dir / "zig"
    if zig_bin.is_file():
        log_info(f"zig is already installed: {zig_bin}")
        return zig_bin

    host_platform = zig_platform()
    if host_platform is None:
        log_warn(
            f"no pinned zig {REQUIRED_ZIG_VERSION} for "
            f"{platform.system()}/{platform.machine()}; install zig manually"
        )
        return None

    log_info(f"Installing zig {REQUIRED_ZIG_VERSION} ({host_platform})...")
    if IS_DRY_RUN:
        log_warn("[DRY-RUN] would download and install zig")
        return None
    url = ZIG_URL_TEMPLATE.format(v=REQUIRED_ZIG_VERSION, zig_platform=host_platform)
    archive = (
        pathlib.Path(tempfile.gettempdir())
        / f"zig-{host_platform}-{REQUIRED_ZIG_VERSION}.tar.xz"
    )
    if not download_file(url, archive, ZIG_SHA256[host_platform]):
        log_warn("zig archive could not be obtained")
        return None
    zig_dir.mkdir(parents=True, exist_ok=True)
    res = run_cmd(
        ["tar", "-xJf", str(archive), "-C", str(zig_dir), "--strip-components=1"],
        check=False,
    )
    archive.unlink(missing_ok=True)
    if res.returncode != 0 or not zig_bin.is_file():
        log_warn(f"Failed to extract the zig archive for {host_platform}")
        return None

    usr_local_bin = pathlib.Path("/usr/local/bin")
    usr_local_bin.mkdir(parents=True, exist_ok=True)
    symlink = usr_local_bin / "zig"
    try:
        if symlink.is_symlink() or symlink.exists():
            symlink.unlink(missing_ok=True)
        symlink.symlink_to(zig_bin)
        log_info(f"Linked zig executable to {symlink}")
    except OSError as e:
        log_warn(f"Could not symlink {symlink}: {e}")
    return zig_bin


def check_zig() -> None:
    if install_zig() is not None:
        return
    msg = (
        f"zig {REQUIRED_ZIG_VERSION} is required but could not be installed "
        "automatically. Install it manually, or run the build inside the "
        "builder container."
    )
    if IS_DRY_RUN:
        log_warn(f"[DRY-RUN] {msg}")
    else:
        log_error(msg)


def check_build_toolchain() -> None:
    required = ["make", "clang", "gcc", "nasm"]
    missing = []
    for tool in required:
        if not shutil.which(tool):
            missing.append(tool)

    has_mingw = shutil.which("x86_64-w64-mingw32-gcc") or shutil.which(
        "i686-w64-mingw32-gcc"
    )
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


# Path to the SilentMoonwalk desync core relative to core_dir.
SMW_ASM_REL = pathlib.Path("lib/syscall/smw/csrc/DesyncSpoofer.asm")
SMW_SYSO_REL = pathlib.Path("lib/syscall/smw/desyncspoofer.syso")

# The Linux stager module is built later, on the operator host, from the
# installed modules/ tree. That tree does not ship vendor/, so the pinned
# malasada stage0 size must be captured here, while the vendored blob is still
# available. malasada is pinned, so this size is static for a given build.
MALASADA_STAGE0_REL = pathlib.Path(
    "vendor/github.com/sliverarmory/malasada/internal/stage0/stage0_linux_amd64.bin"
)
MALASADA_STAGE0_LEN_REL = pathlib.Path(
    "modules/stager_linux/malasada_stage0_len.mk"
)


def assemble_smw(core_dir: pathlib.Path) -> None:
    """Assemble the SilentMoonwalk desync core into a .syso object.

    The Go linker consumes .syso files found in a package directory, so the
    cgo build of lib/syscall/smw needs desyncspoofer.syso to exist. It is
    generated here (and via `go generate` / `make -C lib/syscall/smw`) rather
    than committed, so the NASM source stays the single source of truth and
    only the build environment needs nasm installed.
    """
    asm_file = core_dir / SMW_ASM_REL
    syso_file = core_dir / SMW_SYSO_REL

    if not asm_file.is_file():
        log_error(f"SilentMoonwalk assembly not found: {asm_file}")
        return

    # Skip the rebuild when the object is already up to date.
    try:
        if (
            syso_file.is_file()
            and syso_file.stat().st_mtime >= asm_file.stat().st_mtime
        ):
            log_info(
                f"SilentMoonwalk .syso is up to date: {syso_file.relative_to(core_dir)}"
            )
            return
    except OSError:
        pass

    nasm = shutil.which("nasm")
    if not nasm:
        log_error(
            "nasm not found. Install nasm (see Dockerfile) or run the build inside the builder container."
        )
        return

    cmd = f'{nasm} -f win64 "{asm_file}" -o "{syso_file}"'
    log_info(f"Assembling SilentMoonwalk desync core: {cmd}")
    if IS_DRY_RUN:
        return
    res = run_cmd(cmd, check=False, cwd=str(core_dir), shell=True)
    if res.returncode != 0 or not syso_file.is_file():
        log_error(f"Failed to assemble SilentMoonwalk desync core: {cmd}")


def record_malasada_stage0_size(core_dir: pathlib.Path) -> None:
    """Record the pinned malasada stage0 size for the Linux stager module.

    The stager maps only the stage0 shellcode executable and keeps the
    appended agent payload read-only, so it needs stage0's length at build
    time. The module is built from the installed modules/ tree (no vendor/),
    hence this is captured while the vendored binary is still available.
    """
    stage0 = core_dir / MALASADA_STAGE0_REL
    if not stage0.is_file():
        log_warn(
            f"malasada stage0 not found at {stage0}; "
            "the Linux stager will fall back to mapping the whole blob RX"
        )
        return
    size = stage0.stat().st_size
    out = core_dir / MALASADA_STAGE0_LEN_REL
    write_text_atomic(
        out,
        "# Generated by core/build.py -- do not edit.\n"
        "# Length in bytes of the malasada stage0 shellcode prepended to the\n"
        "# Linux agent payload; the stager maps only this prefix executable.\n"
        f"MALASADA_STAGE0_LEN := {size}\n",
    )
    log_info(f"Recorded malasada stage0 size ({size} bytes) for stager_linux")


def install_donut(
    target_dir: pathlib.Path, search_dir: pathlib.Path | None = None
) -> None:
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
            res = run_cmd(
                ["tar", "-xzf", str(donut_archive), "-C", str(tmp_path)], check=False
            )
            if res.returncode == 0:
                donut_bin = None
                for p in tmp_path.rglob("donut"):
                    if p.is_file():
                        donut_bin = p
                        break
                if donut_bin:
                    bin_target = target_dir / "bin"
                    bin_target.mkdir(parents=True, exist_ok=True)
                    copy2_atomic(donut_bin, bin_target / "donut")
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


def install_crystalpalace(
    target_dir: pathlib.Path, search_dir: pathlib.Path | None = None
) -> None:
    """Install the Crystal Palace distribution into the Crystal-Kit module.

    The distribution is gitignored, so the build fetches it where crystal_pack
    expects it. The archive is SHA-256 verified before extraction; it ships a
    top-level crystalpalace/ directory, so extracting into target_dir yields
    target_dir/crystalpalace/crystalpalace.jar.
    """
    installed = target_dir / "crystalpalace" / "crystalpalace.jar"
    if installed.is_file():
        log_info(f"Crystal Palace already installed at {installed}")
        return

    archive = None
    if search_dir and (search_dir / CRYSTALPALACE_ARCHIVE_NAME).is_file():
        archive = search_dir / CRYSTALPALACE_ARCHIVE_NAME
    if archive is None:
        tmp_archive = (
            pathlib.Path(tempfile.gettempdir()) / CRYSTALPALACE_ARCHIVE_NAME
        )
        if download_file(CRYSTALPALACE_URL, tmp_archive, CRYSTALPALACE_SHA256):
            archive = tmp_archive
    if archive is None:
        log_warn(
            "Crystal Palace archive could not be obtained; crystal_pack will "
            "not work until it is installed"
        )
        return
    if not verify_sha256(archive, CRYSTALPALACE_SHA256):
        archive.unlink(missing_ok=True)
        log_error("Crystal Palace checksum verification failed; refusing to extract")

    log_info("Extracting and installing Crystal Palace...")
    target_dir.mkdir(parents=True, exist_ok=True)
    res = run_cmd(["tar", "-xzf", str(archive), "-C", str(target_dir)], check=False)
    if res.returncode == 0 and installed.is_file():
        log_success(f"Installed Crystal Palace to {installed.parent}")
    else:
        log_warn(f"Failed to extract Crystal Palace archive {archive}")


def agent_build_tags(mode: str) -> str:
    """Build tags for agent executables (cgo and pure Go).

    The full feature set is the default so an untagged build keeps every
    transport; ``--agent-slim``/``--agent-tags`` add the requested tags.
    """
    base = "netgo agent" if mode == "--debug" else "netgo release agent"
    return f"{base} {AGENT_EXTRA_TAGS}" if AGENT_EXTRA_TAGS else base


def agent_shared_tags(mode: str) -> str:
    """Build tags for the agent c-shared object (Linux .so / Windows DLL)."""
    base = "emp3r0r_so" if mode == "--debug" else "release emp3r0r_so"
    return f"{base} {AGENT_EXTRA_TAGS}" if AGENT_EXTRA_TAGS else base


def resolve_agent_tags(args: "argparse.Namespace") -> str:
    """Resolve the extra agent build tags from CLI flags and environment.

    ``--agent-slim`` (or ``EMP3R0R_SLIM_AGENT=1``) adds the recommended
    exclusion preset; ``--agent-tags`` (or ``EMP3R0R_AGENT_TAGS``) adds an
    arbitrary user-supplied set. When both are present they are combined, so a
    user can start from the slim preset and add or replace tags freely.
    """
    groups = []
    if getattr(args, "agent_slim", False) or os.environ.get(
        "EMP3R0R_SLIM_AGENT", "0"
    ).lower() in ("1", "true", "yes"):
        groups.append(SLIM_AGENT_TAGS)

    extra = getattr(args, "agent_tags", "") or os.environ.get(
        "EMP3R0R_AGENT_TAGS", ""
    )
    extra = extra.strip()
    if extra:
        groups.append(extra)

    return " ".join(g for g in groups if g).strip()


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

    tags = agent_build_tags(arg1)
    win_gui_flag = (
        "-H=windowsgui " if (arg1 != "--debug" and os_name == "windows") else ""
    )

    current_ldflags = ldflags
    if extra_extldflags:
        current_ldflags += f" -extldflags '{extra_extldflags}'"

    out_file = resolve_output_path(output, temp_dir)
    env = os.environ.copy()
    env["CGO_ENABLED"] = "0"
    env["GOARCH"] = arch
    env["GOOS"] = os_name

    cmd_str = (
        f"{gobuild_cmd} {build_opt} {extra_flags} -trimpath -buildvcs=false "
        f'-tags \'{tags}\' -o "{out_file}" -ldflags="{win_gui_flag}{current_ldflags}"'
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

    tags = agent_build_tags(arg1)

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

    out_file = resolve_output_path(output, temp_dir)
    env = os.environ.copy()
    env["CGO_ENABLED"] = "1"
    env["CC"] = cc_cmd
    env["GOARCH"] = arch
    env["GOOS"] = os_name

    cmd_str = (
        f"{gobuild_cmd} {build_opt} {extra_flags} -trimpath -buildvcs=false "
        f"-tags '{tags}' -o \"{out_file}\" -ldflags=\"{ldflags} -linkmode external -extldflags '{extldflags}'\""
    )

    print(
        f'Running: CGO_ENABLED=1 CC="{cc_cmd}" GOARCH={arch} GOOS={os_name} {cmd_str}'
    )
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

    tags = agent_shared_tags(arg1)
    # mingw-w64's DLL pseudo-relocation startup (_pei386_runtime_relocator)
    # calls alloca() with a runtime-computed size, which the compiler lowers to
    # a ___chkstk_ms stack-probe call. zig 0.16 honours -nostdlib by dropping
    # compiler-rt (the only provider of that helper); zig 0.13 always linked
    # compiler-rt regardless. Link it back explicitly with -lgcc, which resolves
    # to zig's bundled compiler_rt.lib, or lld-link fails on the undefined
    # symbol. The mingw DLL is therefore built with no default runtime. Linux
    # c-shared objects are loaded by ld-linux and must keep libc: the Go cgo
    # runtime and memmod reference libc symbols such as `environ`, and
    # -nostdlib leaves them undefined so the payload dies with a symbol lookup
    # error before Go ever starts.
    extldflags = "-Wl,--gc-sections"
    if os_name == "windows":
        extldflags = "-lgcc -nostdlib -nodefaultlibs " + extldflags
    if arg1 != "--debug":
        extldflags = f"-s {extldflags}"

    win_gui_flag = (
        "-H=windowsgui " if (arg1 != "--debug" and os_name == "windows") else ""
    )
    out_file = resolve_output_path(output, temp_dir)

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
        # Route every Linux target through zig so all artifacts share one
        # toolchain and the oldest supported ABI (glibc 2.17). amd64 was
        # previously omitted here and silently fell back to the builder's
        # system GCC (manylinux2014 / CentOS 7), an old, differently
        # configured compiler, which broke the c-shared stub.
        zig_target = {
            "amd64": "x86_64-linux-gnu.2.17",
            "386": "x86-linux-gnu.2.17",
            "arm": "arm-linux-gnueabihf.2.17",
            "arm64": "aarch64-linux-gnu.2.17",
            "riscv64": "riscv64-linux-musl",
        }.get(arch)
        if zig_target:
            env["CC"] = f"zig cc -target {zig_target}"

    # The agent c-shared object is linked by zig/lld so it stays pinned to
    # glibc 2.17. lld leaves R_*_RELATIVE addends out of the init-array section
    # on disk; tools.materializeInitArray() resolves them before malasada reads
    # the array, so no host linker is needed here.
    cmd_str = (
        f'{gobuild_cmd} {build_opt} -trimpath -buildvcs=false -tags "{tags}" '
        f'-o "{out_file}" -buildmode c-shared -ldflags="{win_gui_flag}{ldflags} -linkmode external -extldflags \'{extldflags}\'"'
    )

    print(f"Running shared object build for {os_name} {arch}: {cmd_str}")
    agent_cmd_dir = core_dir / "cmd" / "agent"
    res = run_cmd(cmd_str, check=False, cwd=agent_cmd_dir, env=env, shell=True)
    if res.returncode != 0:
        log_error(f"Failed to build shared object for {os_name} {arch}")


# ---------------------------------------------------------------------------
# Target filter helpers
# ---------------------------------------------------------------------------

# Lightweight preset: linux/amd64 exe+so and windows/amd64 exe+dll.
LIGHTWEIGHT_TARGETS: frozenset[str] = frozenset(
    {
        "linux/amd64",
        "windows/amd64",
    }
)


def parse_targets(targets_str: str) -> frozenset[str]:
    """Parse a comma-separated 'os/arch' target string into a frozenset.

    Each token must be in the form 'OS/ARCH'. Case is normalised to lowercase.
    An empty string or None returns an empty frozenset (= build all targets).
    """
    if not targets_str:
        return frozenset()
    tokens = {t.strip().lower() for t in targets_str.split(",") if t.strip()}
    valid_os = {"linux", "windows"}
    valid_arch = {"amd64", "386", "arm", "arm64", "mips", "mips64", "riscv64", "ppc64"}
    for tok in tokens:
        parts = tok.split("/")
        if len(parts) != 2 or parts[0] not in valid_os or parts[1] not in valid_arch:
            log_error(
                f"Invalid target '{tok}'. Expected 'OS/ARCH', e.g. 'linux/amd64'. "
                f"Valid OS: {sorted(valid_os)}, valid ARCH: {sorted(valid_arch)}"
            )
    return frozenset(tokens)


def want_target(os_name: str, arch: str, target_filter: frozenset[str]) -> bool:
    """Return True if the given OS/arch combination should be built.

    An empty filter means 'build everything'.
    """
    if not target_filter:
        return True
    return f"{os_name}/{arch}" in target_filter


def resolve_target_filter(args: "argparse.Namespace") -> frozenset[str]:
    """Determine the effective target filter from CLI args and env vars.

    Priority (highest first):
      1. --lightweight flag
      2. EMP3R0R_LIGHTWEIGHT=1 env var
      3. --targets CLI option
      4. EMP3R0R_TARGETS env var
      5. Empty set (build all)
    """
    if getattr(args, "lightweight", False) or os.environ.get(
        "EMP3R0R_LIGHTWEIGHT", "0"
    ).lower() in ("1", "true", "yes"):
        log_info(
            f"Lightweight build: restricting targets to {sorted(LIGHTWEIGHT_TARGETS)}"
        )
        return LIGHTWEIGHT_TARGETS

    raw = getattr(args, "targets", None) or os.environ.get("EMP3R0R_TARGETS", "")
    if raw:
        filt = parse_targets(raw)
        log_info(f"Target filter active: {sorted(filt)}")
        return filt

    return frozenset()  # build all


def resolve_output_path(output: str, temp_dir: pathlib.Path) -> pathlib.Path:
    """Resolve a build output path against the temporary staging directory.

    Callers may pass a bare filename (staged under temp_dir, as the full build
    does) or an absolute path (used by --build-payload to drop exactly one
    artefact where the caller asked for it).
    """
    out_file = pathlib.Path(output)
    if not out_file.is_absolute():
        out_file = temp_dir / out_file
    return out_file


def resolve_mod_opt(
    core_dir: pathlib.Path, go_bin: str, auto_vendor: bool = True
) -> str:
    """Return the ``-mod`` flag for a Go build.

    Uses the existing vendor/ tree when present. When it is absent and
    ``auto_vendor`` is set (the full build) the dependencies are vendored so
    the resulting tree is self-contained; a targeted --build-payload build
    passes ``auto_vendor=False`` and falls back to the module cache instead of
    rewriting the source tree for a single artefact.
    """
    vendor_dir = core_dir / "vendor"
    mod_txt = vendor_dir / "modules.txt"

    if vendor_dir.is_dir() and mod_txt.is_file():
        log_info("Using existing vendor/ directory for local modules")
        return "-mod=vendor"

    if not auto_vendor:
        log_info("vendor/ directory not found; using the Go module cache")
        return ""

    log_info(
        "vendor/ directory missing or incomplete, attempting to vendor dependencies..."
    )
    res = run_cmd([go_bin, "mod", "vendor"], check=False, cwd=core_dir)
    if res.returncode == 0:
        log_info("Successfully vendored modules")
        return "-mod=vendor"
    log_warn("go mod vendor failed; falling back to default Go module resolution")
    return ""


def resolve_gobuild(
    go_bin: str, mod_opt: str, debug: bool, ldflags: str
) -> tuple[str, str, str]:
    """Resolve the Go build command and ldflags for the requested mode.

    Release builds are obfuscated with garble unless ``EMP3R0R_DISABLE_GARBLE``
    is set; debug builds (and garble-disabled release builds) use plain go and
    keep their symbols. Returns ``(gobuild_cmd, build_opt, ldflags)``.
    """
    if debug:
        return go_bin, f"build {mod_opt}".strip(), ldflags

    disable_garble = os.environ.get("EMP3R0R_DISABLE_GARBLE", "0").lower() in (
        "1",
        "true",
        "yes",
    )
    ldflags += " -s -w"
    if disable_garble:
        log_info("Garble disabled by EMP3R0R_DISABLE_GARBLE, using plain go build")
        return go_bin, f"build {mod_opt}".strip(), ldflags

    log_info("Using garble for obfuscation")
    if not shutil.which("garble"):
        log_error(
            "garble not found. It should be installed in the builder container."
        )
    return "garble", f"-tiny -seed=random build {mod_opt}".strip(), ldflags


# ---------------------------------------------------------------------------
# Core build function
# ---------------------------------------------------------------------------


def build(
    arg1: str,
    temp_dir: pathlib.Path,
    core_dir: pathlib.Path,
    target_filter: frozenset[str] | None = None,
) -> None:
    """Build all emp3r0r components.

    Args:
        arg1: Build mode flag (``--debug``, ``--install``, ``--release``, …).
        temp_dir: Temporary staging directory for build artefacts.
        core_dir: Root of the ``core/`` source tree.
        target_filter: Set of ``'os/arch'`` strings that restrict which agent
            stubs and shared objects are built.  An empty set or ``None`` means
            build every target (default full build).
    """
    if target_filter is None:
        target_filter = frozenset()

    check_build_toolchain()
    go_bin = check_required_go()
    check_disk_space(core_dir)

    mod_opt = resolve_mod_opt(core_dir, go_bin)

    check_zig()
    assemble_smw(core_dir)
    record_malasada_stage0_size(core_dir)

    crystal_kit_dir = core_dir / "modules" / "Crystal-Kit"
    if crystal_kit_dir.is_dir():
        install_crystalpalace(crystal_kit_dir)

    magic_str = hashlib.sha256(os.urandom(32)).hexdigest()
    version = get_version(core_dir)

    ldflags = (
        f"-v -X 'github.com/jm33-m0/emp3r0r/core/internal/def.MagicString={magic_str}' "
        f"-X 'github.com/jm33-m0/emp3r0r/core/internal/def.Version={version}'"
    )

    gobuild_cmd, build_opt, ldflags = resolve_gobuild(
        go_bin, mod_opt, arg1 == "--debug", ldflags
    )

    if target_filter:
        log_info(
            f"Active target filter: {sorted(target_filter)} — skipping all other stubs"
        )
    else:
        log_info("No target filter: building all platforms")

    # ── C2 server binaries (always built, no target filter) ──────────────────
    # `with_gvisor` is required by the operator-side tun2socks engine
    # (internal/cc/base/tun2socks): it builds the gVisor user-space TCP stack
    # into the operator console. cat/listener do not use it.

    log_info("Building CC")
    env_cgo0 = os.environ.copy()
    env_cgo0["CGO_ENABLED"] = "0"
    cc_cmd = f"{go_bin} build {mod_opt} -tags with_gvisor -buildvcs=false -o \"{temp_dir / 'cc.exe'}\" -ldflags=\"{ldflags}\""
    res = run_cmd(
        cc_cmd, check=False, cwd=core_dir / "cmd" / "cc", env=env_cgo0, shell=True
    )
    if res.returncode != 0:
        log_error("Failed to build CC")

    log_info("Building cat")
    cat_cmd = f"{go_bin} build {mod_opt} -buildvcs=false -o \"{temp_dir / 'cat.exe'}\" -ldflags=\"{ldflags}\""
    res = run_cmd(
        cat_cmd, check=False, cwd=core_dir / "cmd" / "cat", env=env_cgo0, shell=True
    )
    if res.returncode != 0:
        log_error("Failed to build cat")

    log_info("Building listener")
    listener_cmd = f"{go_bin} build {mod_opt} -buildvcs=false -o \"{temp_dir / 'listener.exe'}\" -ldflags=\"{ldflags}\""
    res = run_cmd(
        listener_cmd,
        check=False,
        cwd=core_dir / "cmd" / "listener",
        env=env_cgo0,
        shell=True,
    )
    if res.returncode != 0:
        log_error("Failed to build listener")

    if arg1 != "--debug":
        ldflags += " -buildid="

    pie_flags = "-buildmode=pie"
    ext_pie = "-static-pie"

    # Helper so call-sites stay readable.
    def _want(os_name: str, arch: str) -> bool:
        return want_target(os_name, arch, target_filter)

    # ── Linux agent stubs ────────────────────────────────────────────────────
    if _want("linux", "amd64"):
        build_agent_cgo(
            "amd64",
            "linux",
            "stub-amd64",
            pie_flags,
            ext_pie,
            arg1,
            ldflags,
            temp_dir,
            core_dir,
            gobuild_cmd,
            build_opt,
        )
    if _want("linux", "386"):
        build_agent_cgo(
            "386",
            "linux",
            "stub-386",
            pie_flags,
            ext_pie,
            arg1,
            ldflags,
            temp_dir,
            core_dir,
            gobuild_cmd,
            build_opt,
        )
    if _want("linux", "arm"):
        build_agent_pure(
            "arm",
            "linux",
            "stub-arm",
            "",
            "",
            arg1,
            ldflags,
            temp_dir,
            core_dir,
            gobuild_cmd,
            build_opt,
        )
    if _want("linux", "arm64"):
        build_agent_cgo(
            "arm64",
            "linux",
            "stub-arm64",
            pie_flags,
            ext_pie,
            arg1,
            ldflags,
            temp_dir,
            core_dir,
            gobuild_cmd,
            build_opt,
        )
    if _want("linux", "mips"):
        build_agent_pure(
            "mips",
            "linux",
            "stub-mips",
            "",
            "",
            arg1,
            ldflags,
            temp_dir,
            core_dir,
            gobuild_cmd,
            build_opt,
        )
    if _want("linux", "mips64"):
        build_agent_pure(
            "mips64",
            "linux",
            "stub-mips64",
            "",
            "",
            arg1,
            ldflags,
            temp_dir,
            core_dir,
            gobuild_cmd,
            build_opt,
        )
    if _want("linux", "riscv64"):
        build_agent_cgo(
            "riscv64",
            "linux",
            "stub-riscv64",
            pie_flags,
            ext_pie,
            arg1,
            ldflags,
            temp_dir,
            core_dir,
            gobuild_cmd,
            build_opt,
        )
    if _want("linux", "ppc64"):
        build_agent_pure(
            "ppc64",
            "linux",
            "stub-ppc64",
            "",
            "",
            arg1,
            ldflags,
            temp_dir,
            core_dir,
            gobuild_cmd,
            build_opt,
        )

    # ── Windows agent stubs ──────────────────────────────────────────────────
    if _want("windows", "amd64"):
        build_agent_pure(
            "amd64",
            "windows",
            "stub-win-amd64",
            "",
            "",
            arg1,
            ldflags,
            temp_dir,
            core_dir,
            gobuild_cmd,
            build_opt,
        )
    if _want("windows", "386"):
        build_agent_pure(
            "386",
            "windows",
            "stub-win-386",
            "",
            "",
            arg1,
            ldflags,
            temp_dir,
            core_dir,
            gobuild_cmd,
            build_opt,
        )
    if _want("windows", "arm64"):
        build_agent_pure(
            "arm64",
            "windows",
            "stub-win-arm64",
            "",
            "",
            arg1,
            ldflags,
            temp_dir,
            core_dir,
            gobuild_cmd,
            build_opt,
        )

    # ── Shared Objects ───────────────────────────────────────────────────────
    if _want("windows", "amd64"):
        build_shared_object(
            "amd64",
            "windows",
            "stub-win-amd64.dll",
            arg1,
            ldflags,
            temp_dir,
            core_dir,
            gobuild_cmd,
            build_opt,
        )
    if _want("windows", "386"):
        build_shared_object(
            "386",
            "windows",
            "stub-win-386.dll",
            arg1,
            ldflags,
            temp_dir,
            core_dir,
            gobuild_cmd,
            build_opt,
        )
    if _want("windows", "arm64"):
        build_shared_object(
            "arm64",
            "windows",
            "stub-win-arm64.dll",
            arg1,
            ldflags,
            temp_dir,
            core_dir,
            gobuild_cmd,
            build_opt,
        )
    if _want("linux", "amd64"):
        build_shared_object(
            "amd64",
            "linux",
            "stub-amd64.so",
            arg1,
            ldflags,
            temp_dir,
            core_dir,
            gobuild_cmd,
            build_opt,
        )
    if _want("linux", "386"):
        build_shared_object(
            "386",
            "linux",
            "stub-386.so",
            arg1,
            ldflags,
            temp_dir,
            core_dir,
            gobuild_cmd,
            build_opt,
        )
    if _want("linux", "arm"):
        build_shared_object(
            "arm",
            "linux",
            "stub-arm.so",
            arg1,
            ldflags,
            temp_dir,
            core_dir,
            gobuild_cmd,
            build_opt,
        )
    if _want("linux", "riscv64"):
        build_shared_object(
            "riscv64",
            "linux",
            "stub-riscv64.so",
            arg1,
            ldflags,
            temp_dir,
            core_dir,
            gobuild_cmd,
            build_opt,
        )

    # ── Modules (make_all.sh) — always run, target-filtering not applicable ──
    # Native modules are OS/arch-agnostic build artefacts (BOFs, etc.) so we
    # do not suppress them based on the target filter.
    log_info("Building complex modules with make_all.sh...")
    modules_dir = core_dir / "modules"
    module_env = os.environ.copy()
    module_env["EMP3R0R_DEBUG"] = "1" if arg1 == "--debug" else "0"
    if modules_dir.is_dir():
        for mod_dir in modules_dir.iterdir():
            make_all = mod_dir / "make_all.sh"
            if mod_dir.is_dir() and make_all.is_file():
                log_info(
                    f"Running make_all.sh in {mod_dir.name} ({'debug' if arg1 == '--debug' else 'release'})"
                )
                try:
                    make_all.chmod(0o755)
                except Exception:
                    pass
                res = run_cmd(
                    ["./make_all.sh"], check=False, cwd=mod_dir, env=module_env
                )
                if res.returncode != 0:
                    log_warn(
                        f"Failed to build modules in {mod_dir.name} via make_all.sh"
                    )

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
        log_error(
            "emp3r0r is not installed. Please run --install on the C2 server first"
        )

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
            copy2_atomic(bin_src, kit_dir / "bin" / "emp3r0r")
        else:
            log_error("Failed to copy emp3r0r launcher")

        for binary in ["emp3r0r-cc", "emp3r0r-cat"]:
            src = lib_src / binary
            if src.exists():
                copy2_atomic(src, kit_dir / "lib" / "emp3r0r" / binary)
            else:
                log_error(f"Failed to copy {binary}")

        listener_src = installed_prefix / "bin" / "emp3r0r-listener"
        if listener_src.exists():
            copy2_atomic(listener_src, kit_dir / "bin" / "emp3r0r-listener")
        else:
            log_warn(f"emp3r0r-listener not found at {listener_src}; skipping")

        for d in ["build", "modules", "tmux", "zig"]:
            src_dir = lib_src / d
            if src_dir.is_dir():
                shutil.copytree(
                    src_dir,
                    kit_dir / "lib" / "emp3r0r" / d,
                    dirs_exist_ok=True,
                    copy_function=copy2_atomic,
                )
            else:
                log_warn(f"{src_dir} not found; operator package may be incomplete")

        log_info(f"Downloading donut package from {DONUT_URL}...")
        download_file(DONUT_URL, kit_dir / DONUT_ARCHIVE_NAME)
        install_donut(kit_dir / "lib" / "emp3r0r", search_dir=kit_dir)

        # Copy Python installer directly from repo root
        root_install_py = core_dir.parent / "install.py"
        if root_install_py.is_file():
            copy2_atomic(root_install_py, kit_dir / "install.py")
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
            [
                "tar",
                "-I",
                "zstd",
                "-cpf",
                str(bundle_tar),
                "-C",
                str(stage_path),
                "emp3r0r-operator-kit",
            ],
            check=False,
        )
        if res.returncode != 0:
            log_error("Failed to create operator package")

        log_success(f"Created portable operator package: {bundle_tar}")
        log_success("Transfer to your operator machine, then:")
        log_success(
            f"  tar -I zstd -xpf {operator_bundle_name} && ./emp3r0r-operator-kit/install.py"
        )


def remove_obsolete_wireguard_config() -> None:
    """Remove the tmpfiles entry older installs used to create /var/run/wireguard.

    WireGuard now runs entirely in userspace (wireguard-go plus a gVisor
    netstack), so emp3r0r-cc needs no CAP_NET_ADMIN, no kernel TUN device and
    no WireGuard socket directory. Deleting this emp3r0r-specific entry stops
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


def do_install(prefix: str, temp_dir: pathlib.Path, core_dir: pathlib.Path) -> None:
    if (
        not IS_DRY_RUN
        and os.name != "nt"
        and hasattr(os, "geteuid")
        and os.geteuid() != 0
    ):
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
            shutil.copytree(
                temp_dir / "tmux",
                data_dir / "tmux",
                dirs_exist_ok=True,
                copy_function=copy2_atomic,
            )
        if (temp_dir / "modules").is_dir():
            shutil.copytree(
                temp_dir / "modules",
                data_dir / "modules",
                dirs_exist_ok=True,
                copy_function=copy2_atomic,
            )

        for stub in temp_dir.glob("stub*"):
            copy2_atomic(stub, build_dir / stub.name)

        tmux_conf = data_dir / "tmux" / ".tmux.conf"
        if tmux_conf.is_file():
            tmux_sh_dir = str(data_dir / "tmux" / "sh")
            content = tmux_conf.read_text(encoding="utf-8")
            content = content.replace("~/sh", tmux_sh_dir)
            write_text_atomic(tmux_conf, content)

        if (temp_dir / "cc.exe").is_file():
            (temp_dir / "cc.exe").chmod(0o755)
        if (temp_dir / "cat.exe").is_file():
            (temp_dir / "cat.exe").chmod(0o755)

        if (temp_dir / "emp3r0r").is_file():
            copy2_atomic(temp_dir / "emp3r0r", bin_dir / "emp3r0r")
            (bin_dir / "emp3r0r").chmod(0o755)
        if (temp_dir / "listener.exe").is_file():
            copy2_atomic(temp_dir / "listener.exe", bin_dir / "emp3r0r-listener")
            (bin_dir / "emp3r0r-listener").chmod(0o755)

        if (temp_dir / "cc.exe").is_file():
            copy2_atomic(temp_dir / "cc.exe", data_dir / "emp3r0r-cc")
            (data_dir / "emp3r0r-cc").chmod(0o755)
        if (temp_dir / "cat.exe").is_file():
            copy2_atomic(temp_dir / "cat.exe", data_dir / "emp3r0r-cat")
            (data_dir / "emp3r0r-cat").chmod(0o755)

    install_donut(data_dir, search_dir=temp_dir)
    # zig ships with emp3r0r so the C2 can build the C modules on the host.
    install_zig(data_dir)

    is_container = (
        pathlib.Path("/.dockerenv").exists()
        or pathlib.Path("/run/.containerenv").exists()
    )

    if not is_container:
        # WireGuard runs entirely in userspace now, so there is no capability to
        # grant and no /var/run/wireguard socket directory to create. Clean up
        # the artifacts older kernel-WireGuard installs left behind.
        remove_obsolete_wireguard_config()

        cc_bin = data_dir / "emp3r0r-cc"
        bash_comp_dir = pathlib.Path("/etc/bash_completion.d")
        if bash_comp_dir.is_dir():
            res = run_cmd(
                [str(cc_bin), "completion", "bash"], check=False, capture_output=True
            )
            if res.returncode == 0 and res.stdout:
                try:
                    write_text_atomic(bash_comp_dir / "emp3r0r", res.stdout)
                    log_info(
                        "Installed Bash completion to /etc/bash_completion.d/emp3r0r"
                    )
                except OSError as e:
                    log_warn(
                        f"Could not install Bash completion (overwrite failed: {e}); continuing"
                    )
    else:
        log_info("Running inside container, skipping autocomplete setup")

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

    remove_obsolete_wireguard_config()

    log_success("emp3r0r has been removed")


def prepare_misc_files(core_dir: pathlib.Path, temp_dir: pathlib.Path) -> None:
    log_info("Preparing misc files")
    for name in ["tmux", "modules", "emp3r0r"]:
        src = core_dir / name
        if src.exists():
            if src.is_dir():
                shutil.copytree(
                    src, temp_dir / name, dirs_exist_ok=True, copy_function=copy2_atomic
                )
            else:
                copy2_atomic(src, temp_dir / name)

    build_py = core_dir / "build.py"
    if build_py.exists():
        copy2_atomic(build_py, temp_dir / "build.py")


def create_tar(core_dir: pathlib.Path, temp_dir: pathlib.Path) -> None:
    prepare_misc_files(core_dir, temp_dir)
    log_info("Creating archive...")
    release_tar = core_dir / "emp3r0r.tar.zst"
    res = run_cmd(
        [
            "tar",
            "-I",
            "zstd",
            "-cpf",
            str(release_tar),
            "-C",
            str(temp_dir.parent),
            temp_dir.name,
        ],
        check=False,
    )
    if res.returncode != 0:
        log_error("Failed to create archive")
    log_success("Packaged emp3r0r")


# Payload kinds --build-payload can produce. Each maps to the same helper the
# full build uses for that artefact, so a single payload keeps the full
# build's toolchain, tags, ldflags, and per-build MagicString/Version.
PAYLOAD_KINDS = ("shared", "cgo", "pure")


def build_single_payload(args: argparse.Namespace) -> None:
    """Build exactly one agent payload to ``--payload-output``.

    Mirrors the full build flags for the requested artefact: the same Go
    toolchain/garble policy, the same zig cross-compiler (Linux glibc 2.17),
    tags, buildmode, and the ``MagicString``/``Version`` ldflags. Pass
    ``--payload-magic-string`` to match an already-built C2; otherwise a fresh
    per-build string is generated, exactly like the full build does.
    """
    core_dir = pathlib.Path(__file__).resolve().parent

    if not args.payload_output:
        log_error("--payload-output is required with --build-payload")

    go_bin = check_required_go()
    mod_opt = resolve_mod_opt(core_dir, go_bin, auto_vendor=False)

    kind = args.payload_kind
    if kind in ("shared", "cgo"):
        # These link against libc through zig; pure Go does not need a C compiler.
        check_zig()

    magic_str = args.payload_magic_string or hashlib.sha256(
        os.urandom(32)
    ).hexdigest()
    version = get_version(core_dir)
    ldflags = (
        f"-v -X 'github.com/jm33-m0/emp3r0r/core/internal/def.MagicString={magic_str}' "
        f"-X 'github.com/jm33-m0/emp3r0r/core/internal/def.Version={version}'"
    )
    gobuild_cmd, build_opt, ldflags = resolve_gobuild(
        go_bin, mod_opt, args.payload_debug, ldflags
    )
    if not args.payload_debug:
        ldflags += " -buildid="

    arg1 = "--debug" if args.payload_debug else "--build"
    output = args.payload_output

    with tempfile.TemporaryDirectory(prefix="emp3r0r-payload-") as tmp_dir:
        temp_dir = pathlib.Path(tmp_dir)
        if kind == "shared":
            build_shared_object(
                args.payload_arch,
                args.payload_os,
                output,
                arg1,
                ldflags,
                temp_dir,
                core_dir,
                gobuild_cmd,
                build_opt,
            )
        elif kind == "cgo":
            build_agent_cgo(
                args.payload_arch,
                args.payload_os,
                output,
                "-buildmode=pie",
                "-static-pie",
                arg1,
                ldflags,
                temp_dir,
                core_dir,
                gobuild_cmd,
                build_opt,
            )
        elif kind == "pure":
            build_agent_pure(
                args.payload_arch,
                args.payload_os,
                output,
                "",
                "",
                arg1,
                ldflags,
                temp_dir,
                core_dir,
                gobuild_cmd,
                build_opt,
            )
        else:
            log_error(f"Unknown payload kind: {kind}")

    log_success(
        f"Built {kind} payload for {args.payload_os}/{args.payload_arch} at {output}"
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="emp3r0r Core Build and Installation Script",
        epilog=agent_tag_reference(),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        "--build",
        action="store_true",
        help="Build binaries and agent stubs in temp directory",
    )
    group.add_argument(
        "--install",
        action="store_true",
        help="Build binaries, install to prefix, package operator bundle",
    )
    group.add_argument(
        "--install-only",
        action="store_true",
        help="Skip build; install pre-built binaries",
    )
    group.add_argument(
        "--debug",
        action="store_true",
        help="Build with debug mode (no garble), install, package operator bundle",
    )
    group.add_argument(
        "--release", action="store_true", help="Build and package full release tarball"
    )
    group.add_argument(
        "--uninstall",
        action="store_true",
        help="Remove installed files and completions",
    )
    group.add_argument(
        "--package-operator",
        action="store_true",
        help="Package existing install into operator kit",
    )
    group.add_argument(
        "--build-payload",
        action="store_true",
        help=(
            "Build a single agent payload to --payload-output, using the same "
            "toolchain, tags, and ldflags as the full build"
        ),
    )

    # ── Agent feature selection ───────────────────────────────────────────────
    feat_group = parser.add_argument_group(
        "agent feature selection",
        "Control which optional agent subsystems are compiled in. The default "
        "keeps every transport and feature.",
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
            "Space-separated Go build tags to add to every agent payload, "
            "e.g. 'no_mesh no_kcp' or a custom tag. Combined with "
            "--agent-slim when both are given; C2 binaries are never tagged. "
            "See the tag reference below or --list-agent-tags."
        ),
    )
    parser.add_argument(
        "--list-agent-tags",
        action="store_true",
        help="Print the available agent exclusion tags and exit",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print build and setup commands without executing them",
    )

    # ── Target selection ─────────────────────────────────────────────────────
    tgt_group = parser.add_argument_group(
        "target selection",
        "Restrict which agent stubs/shared-objects are compiled. "
        "C2 binaries (cc, cat, listener) are always built.",
    )
    tgt_excl = tgt_group.add_mutually_exclusive_group()
    tgt_excl.add_argument(
        "--lightweight",
        action="store_true",
        default=False,
        help=(
            "Build only linux/amd64 and windows/amd64 exe/dll targets. "
            "Fastest preset — ideal for development or x86-64-only deployments. "
            "Equivalent to --targets linux/amd64,windows/amd64."
        ),
    )
    tgt_excl.add_argument(
        "--targets",
        metavar="OS/ARCH[,OS/ARCH,...]",
        default="",
        help=(
            "Comma-separated list of OS/arch targets to build, e.g. "
            "'linux/amd64,windows/amd64,windows/386'. "
            "Valid OS values: linux, windows. "
            "Valid arch values: amd64, 386, arm, arm64, mips, mips64, riscv64, ppc64."
        ),
    )

    # ── Single payload ───────────────────────────────────────────────────────
    pay_group = parser.add_argument_group(
        "single payload",
        "Options for --build-payload. Builds exactly one agent artefact.",
    )
    pay_group.add_argument(
        "--payload-kind",
        choices=PAYLOAD_KINDS,
        default="shared",
        help="Artefact kind: shared=c-shared object, cgo=cgo executable, pure=pure Go executable",
    )
    pay_group.add_argument(
        "--payload-os",
        choices=["linux", "windows"],
        default="linux",
        help="Target OS for the payload (default: linux)",
    )
    pay_group.add_argument(
        "--payload-arch",
        default="amd64",
        help="Target arch for the payload (default: amd64)",
    )
    pay_group.add_argument(
        "--payload-output",
        default="",
        help="Output path (absolute) for the payload; required with --build-payload",
    )
    pay_group.add_argument(
        "--payload-debug",
        action="store_true",
        help="Build the payload without garble/stripping",
    )
    pay_group.add_argument(
        "--payload-magic-string",
        default="",
        help=(
            "MagicString to embed via ldflags so the payload interoperates with "
            "an already-built C2; random when omitted"
        ),
    )

    return parser.parse_args()


def main() -> None:
    args = parse_args()

    if getattr(args, "list_agent_tags", False):
        print(agent_tag_reference())
        return

    global IS_DRY_RUN
    if args.dry_run:
        IS_DRY_RUN = True
        os.environ["EMP3R0R_DRY_RUN"] = "1"

    global AGENT_EXTRA_TAGS
    AGENT_EXTRA_TAGS = resolve_agent_tags(args)
    if AGENT_EXTRA_TAGS:
        log_info(f"Agent build tags: {AGENT_EXTRA_TAGS}")

    core_dir = pathlib.Path(__file__).resolve().parent
    prefix = os.environ.get("PREFIX", "/usr/local")

    if args.uninstall:
        do_uninstall(prefix)
        return

    if args.package_operator:
        package_operator_bundle(prefix, core_dir)
        return

    if args.build_payload:
        build_single_payload(args)
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

    # Resolve which agent targets to build (may be an empty set = all).
    target_filter = resolve_target_filter(args)

    with tempfile.TemporaryDirectory(prefix="emp3r0r-build-") as tmp_dir:
        temp_dir = pathlib.Path(tmp_dir)

        if mode == "--release":
            build(mode, temp_dir, core_dir, target_filter)
            create_tar(core_dir, temp_dir)
        elif mode == "--build":
            build(mode, temp_dir, core_dir, target_filter)
        elif mode == "--install-only":
            do_install(prefix, temp_dir, core_dir)
            package_operator_bundle(prefix, core_dir)
        elif mode in ("--install", "--debug"):
            build(mode, temp_dir, core_dir, target_filter)
            prepare_misc_files(core_dir, temp_dir)
            do_install(prefix, temp_dir, core_dir)
            package_operator_bundle(prefix, core_dir)


if __name__ == "__main__":
    main()
