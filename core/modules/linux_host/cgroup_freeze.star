# cgroup_freeze - report, freeze or thaw a process's cgroup v2.
#
# Ported to Starlark from Furtex's edrs/cgroup_freeze.c.
# Upstream project: https://github.com/MatheuZSecurity/Furtex (MIT License,
# Copyright (c) 2026 MatheuZ). See README.md in this directory for attribution.
#
# Freezing a cgroup freezes every process in it, including the agent if it
# shares the cgroup (the common case on a systemd host). We therefore refuse to
# operate on the agent's own cgroup; a target on another cgroup can be frozen.

AT_FDCWD = -100
O_WRONLY = 1


def _proc_dir(pid):
    if not pid or pid == "self":
        return "/proc/self"
    return "/proc/%s" % pid


def _cgroup_rel(pid):
    # cgroup v2 unified hierarchy is the "0::<path>" line.
    data = read_file(_proc_dir(pid) + "/cgroup", default="")
    for line in data.splitlines():
        parts = line.split(":")
        if len(parts) >= 3 and parts[0] == "0":
            return parts[2]
    return ""


def _cgroup_dir(pid):
    rel = _cgroup_rel(pid)
    if not rel:
        return ""
    if rel == "/":
        return "/sys/fs/cgroup"
    return "/sys/fs/cgroup" + rel


def _write_ctl(path, data):
    open_res = sys_call("openat", AT_FDCWD, path, O_WRONLY, 0)
    if open_res["errno"] != 0:
        return open_res["errno"]
    fd = open_res["r1"]
    write_res = sys_call("write", fd, data, len(data))
    sys_call("close", fd)
    return write_res["errno"]


def main(*args):
    action = "show"
    pid = ""
    if args and args[0]:
        action = str_lower(args[0].strip())
    if len(args) > 1 and args[1]:
        pid = args[1].strip()

    target = _cgroup_dir(pid)
    if not target:
        print("[!] cgroup v2 (unified) not found for pid %s" % (pid or "self"))
        return "ERROR: cgroup v2 required"

    self_cg = _cgroup_dir("")
    freeze = read_file(target + "/cgroup.freeze", default="?").strip()
    ctype = read_file(target + "/cgroup.type", default="?").strip()
    print("[*] cgroup=%s type=%s frozen=%s" % (target, ctype, freeze))

    if action == "show":
        return "OK"
    if action != "freeze" and action != "thaw":
        print("[!] unknown action: %s" % action)
        return "ERROR: unknown action"
    if target == self_cg:
        print("[!] refusing to %s the agent's own cgroup (%s)" % (action, target))
        return "ERROR: refusing own cgroup"

    value = "1" if action == "freeze" else "0"
    errno = _write_ctl(target + "/cgroup.freeze", value)
    if errno != 0:
        print("[!] could not write cgroup.freeze=%s (errno=%d)" % (value, errno))
        return "ERROR: write errno=%d" % errno
    print("[+] %s: %s/cgroup.freeze=%s" % (action, target, value))
    return "OK"
