# linux_oom_cage - inspect or set a process's OOM killer score.
#
# Ported to Starlark from Furtex's edrs/oom_cage.c.
# Upstream project: https://github.com/MatheuZSecurity/Furtex (MIT License,
# Copyright (c) 2026 MatheuZ). See README.md in this directory for attribution.
#
# Raising oom_score_adj (making a process more killable) is unprivileged;
# lowering it below the current value (protect) needs CAP_SYS_RESOURCE, so the
# kernel rejects it for an ordinary user and we surface the errno instead of
# aborting.

AT_FDCWD = -100
O_WRONLY = 1


def _base(pid):
    if not pid or pid == "self":
        return "/proc/self"
    return "/proc/%s" % pid


def _write_ctl(path, data):
    # Direct openat/write/close so a permission error becomes a reported errno
    # rather than an engine exception (Starlark has no try/except).
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
    value = ""
    if args and args[0]:
        action = str_lower(args[0].strip())
    if len(args) > 1 and args[1]:
        pid = args[1].strip()
    if len(args) > 2 and args[2]:
        value = args[2].strip()

    base = _base(pid)
    score = read_file(base + "/oom_score", default="?").strip()
    adj = read_file(base + "/oom_score_adj", default="?").strip()
    print("[*] %s oom_score=%s oom_score_adj=%s" % (base, score, adj))

    if action == "show":
        return "OK"
    if action == "protect":
        value = "-1000"
    elif action == "expose":
        value = "1000"
    elif action != "set":
        print("[!] unknown action: %s" % action)
        return "ERROR: unknown action"
    if not value:
        print("[!] 'set' requires a value")
        return "ERROR: value required"

    errno = _write_ctl(base + "/oom_score_adj", value)
    if errno != 0:
        print("[!] could not set oom_score_adj=%s (errno=%d; CAP_SYS_RESOURCE needed to lower it)" % (value, errno))
        return "ERROR: write errno=%d" % errno
    after = read_file(base + "/oom_score_adj", default="?").strip()
    print("[+] oom_score_adj set to %s (now %s)" % (value, after))
    return "OK"
