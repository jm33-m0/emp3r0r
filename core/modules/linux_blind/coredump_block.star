# linux_coredump_block - suppress core dumps and memory-scanner access.
#
# Ported to Starlark from Furtex's edrs/coredump_block.c.
# Upstream project: https://github.com/MatheuZSecurity/Furtex (MIT License,
# Copyright (c) 2026 MatheuZ). See README.md in this directory for attribution.
#
# PR_SET_DUMPABLE=0 also clears the process's coredump_filter-writable flag and
# makes /proc/<pid>/mem unreadable to debuggers/EDR memory scanners. `madv`
# walks the agent's own mappings and marks each MADV_DONTDUMP, excluding them
# from any core file that still gets written.

AT_FDCWD = -100
O_WRONLY = 1

PR_GET_DUMPABLE = 3
PR_SET_DUMPABLE = 4
PR_SET_PTRACER = 0x59616D61
RLIMIT_CORE = 4
MADV_DONTDUMP = 16


def _write(path, data):
    # Direct openat/write keeps control-file writes out of write_file's
    # at-rest encryption and surfaces errno instead of raising.
    res = sys_call("openat", AT_FDCWD, path, O_WRONLY, 0)
    if res["errno"] != 0:
        return res["errno"]
    fd = res["r1"]
    w = sys_call("write", fd, data, len(data))
    sys_call("close", fd)
    return w["errno"]


def _parse_range(line):
    fields = line.split()
    if not fields:
        return 0, 0
    rng = fields[0].split("-")
    if len(rng) != 2:
        return 0, 0
    return int(rng[0], 16), int(rng[1], 16)


def _show():
    filt = read_file("/proc/self/coredump_filter", default="?")
    if not filt:
        filt = "?"
    print(sprintf("  coredump_filter: %s", filt.strip()))
    dump = sys_call("prctl", PR_GET_DUMPABLE, 0, 0, 0, 0)
    print(sprintf("  dumpable:        %d", dump["r1"]))
    pat = read_file("/proc/sys/kernel/core_pattern", default="?")
    print(sprintf("  core_pattern:    %s", (pat or "?").strip()))
    uses = read_file("/proc/sys/kernel/core_uses_pid", default="?")
    print(sprintf("  core_uses_pid:   %s", (uses or "?").strip()))


def _self_block():
    errno = _write("/proc/self/coredump_filter", "0\n")
    print(sprintf("  coredump_filter=0: %s", "ok" if errno == 0 else sprintf("errno=%d", errno)))
    d = sys_call("prctl", PR_SET_DUMPABLE, 0, 0, 0, 0)
    print(sprintf("  PR_SET_DUMPABLE=0: %s", "ok" if d["errno"] == 0 else sprintf("errno=%d", d["errno"])))
    p = sys_call("prctl", PR_SET_PTRACER, 0, 0, 0, 0)
    print(sprintf("  PR_SET_PTRACER=0:  %s", "ok" if p["errno"] == 0 else sprintf("errno=%d", p["errno"])))
    rl = sys_alloc(16)
    write_u64(rl, 0, 0)
    write_u64(rl, 8, 0)
    r = sys_call("prlimit64", 0, RLIMIT_CORE, rl, 0)
    sys_free(rl)
    print(sprintf("  RLIMIT_CORE=0:     %s", "ok" if r["errno"] == 0 else sprintf("errno=%d", r["errno"])))
    print("[+] process is now resistant to core dumps and /proc/self/mem reads")


def _pid_block(pid):
    if not pid:
        print("[!] action=pid requires --pid")
        return "ERROR: pid required"
    errno = _write(sprintf("/proc/%s/coredump_filter", pid), "0\n")
    if errno != 0:
        print(sprintf("[!] /proc/%s/coredump_filter write failed (errno=%d)", pid, errno))
        return sprintf("ERROR: errno=%d", errno)
    print(sprintf("[+] PID %s coredump_filter=0", pid))
    return "OK"


def _madv():
    data = read_file("/proc/self/maps", default="")
    if not data:
        print("[!] /proc/self/maps not readable")
        return "ERROR: no maps"
    count = 0
    for line in data.splitlines():
        start, end = _parse_range(line)
        if start <= 0 or end <= start:
            continue
        res = sys_call("madvise", start, end - start, MADV_DONTDUMP)
        if res["errno"] == 0:
            count += 1
    print(sprintf("[+] MADV_DONTDUMP applied to %d VMA(s)", count))
    return "OK"


def _system():
    failures = 0
    for path, value in (("/proc/sys/kernel/core_pattern", "|/bin/false\n"), ("/proc/sys/fs/suid_dumpable", "0\n")):
        errno = _write(path, value)
        if errno != 0:
            print(sprintf("  [!] %s write failed (errno=%d)", path, errno))
            failures += 1
        else:
            print(sprintf("  [+] %s updated", path))
    print(sprintf("[*] system-wide core dump suppression%s", "" if failures == 0 else " (partial)"))
    return "OK"


def main(*args):
    action = "show"
    pid = ""
    if args and args[0]:
        action = str_lower(args[0].strip())
    if len(args) > 1 and args[1]:
        pid = args[1].strip()

    if action == "show":
        _show()
        return "OK"
    if action == "self":
        _self_block()
        return "OK"
    if action == "pid":
        return _pid_block(pid)
    if action == "madv":
        return _madv()
    if action == "system":
        return _system()
    print(sprintf("[!] unknown action: %s", action))
    return "ERROR: unknown action"
