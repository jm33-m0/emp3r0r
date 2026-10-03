# linux_proc_fd_scan - find processes holding credential/secret files open.
#
# Ported to Starlark from Furtex's edrs/proc_fd_scan.c.
# Upstream project: https://github.com/MatheuZSecurity/Furtex (MIT License,
# Copyright (c) 2026 MatheuZ). See README.md in this directory for attribution.
#
# Only the discovery half is ported: we list matching /proc/<pid>/fd targets but
# do not read their contents, because a blocking read of a pipe/socket/device
# would stall the memory-only agent.

INTERESTING = [
    "shadow", "passwd", ".ssh", "id_rsa", "id_ed25519",
    ".aws", "credentials", ".gnupg", "private", "secret",
    "token", "password", "cert", ".bash_history",
    "kubeconfig", ".kube", "consul", "vault",
]

# read_link(path, default="") is the Go builtin; the default makes a vanished
# or racy /proc symlink read as empty instead of raising (no try/except here).


def _is_pid(name):
    if not name:
        return False
    c = name[0]
    return c >= "0" and c <= "9"


def _interesting(target, filter_sub):
    if filter_sub:
        return str_contains(target, filter_sub)
    low = str_lower(target)
    for pat in INTERESTING:
        if str_contains(low, pat):
            return True
    return False


def _scan_pid(pid, filter_sub):
    found = 0
    fddir = sprintf("/proc/%s/fd", pid)
    for fd in list_dir(fddir):
        target = read_link(sprintf("%s/%s", fddir, fd), default="")
        if not target:
            continue
        # Skip kernel pseudo-targets; they carry no credential path.
        if target in ("", "[]") or str_startswith(target, "socket:") or str_startswith(target, "pipe:") or str_startswith(target, "anon_inode:"):
            continue
        if not _interesting(target, filter_sub):
            continue
        print(sprintf("[pid=%s fd=%s] %s", pid, fd, target))
        found += 1
    return found


def main(*args):
    filter_sub = ""
    pid = ""
    if args and args[0]:
        filter_sub = args[0]
    if len(args) > 1 and args[1]:
        pid = args[1].strip()
    if not filter_sub:
        filter_sub = ""

    total = 0
    if pid:
        print(sprintf("[*] scanning pid %s", pid))
        total = _scan_pid(pid, filter_sub)
    else:
        print("[*] scanning all /proc/<pid>/fd")
        for p in list_dir("/proc"):
            if not _is_pid(p):
                continue
            total += _scan_pid(p, filter_sub)

    print("")
    print(sprintf("[*] %d matching file descriptors", total))
    return "OK"
