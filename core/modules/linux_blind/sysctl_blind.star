# linux_sysctl_blind - show or override the security-relevant kernel sysctls.
#
# Ported to Starlark from Furtex's edrs/sysctl_blind.c.
# Upstream project: https://github.com/MatheuZSecurity/Furtex (MIT License,
# Copyright (c) 2026 MatheuZ). See README.md in this directory for attribution.
#
# This is the write-capable counterpart to the linux_recon suite's
# linux_sysctl_audit.
# `blind` restricts the kernel information sources EDRs read; `open` restores
# permissive values. modules_disabled is deliberately never restored: it is
# irreversible until reboot.

AT_FDCWD = -100
O_WRONLY = 1

CTLS = [
    {
        "key": "kernel.dmesg_restrict",
        "blind": "1",
        "open": "0",
        "desc": "1 = unprivileged processes cannot read the kernel ring buffer",
    },
    {
        "key": "kernel.kptr_restrict",
        "blind": "2",
        "open": "0",
        "desc": "2 = /proc/kallsyms addresses hidden from everyone",
    },
    {
        "key": "kernel.perf_event_paranoid",
        "blind": "3",
        "open": "-1",
        "desc": "3 = perf_event_open restricted (perf-based EDR loses visibility)",
    },
    {
        "key": "kernel.yama.ptrace_scope",
        "blind": "2",
        "open": "0",
        "desc": "2 = only CAP_SYS_PTRACE may ptrace another process",
    },
    {
        "key": "kernel.unprivileged_bpf_disabled",
        "blind": "1",
        "open": "0",
        "desc": "1 = CAP_BPF required for all BPF operations",
    },
    {
        "key": "net.core.bpf_jit_harden",
        "blind": "2",
        "open": "0",
        "desc": "2 = constant blinding for privileged BPF programs",
    },
    {
        "key": "kernel.modules_disabled",
        "blind": "1",
        "open": "",
        "desc": "1 = no new kernel modules can be loaded (irreversible without reboot)",
    },
]


def _is_true(s):
    return str_lower(s) in ("true", "1", "yes", "on")


def _path(key):
    if str_startswith(key, "/"):
        return key
    return "/proc/sys/" + str_replace(key, ".", "/")


def _write(path, val):
    # Direct openat/write so permission failures surface as errno instead of
    # aborting the script, and so write_file's disk encryption is bypassed.
    res = sys_call("openat", AT_FDCWD, path, O_WRONLY, 0)
    if res["errno"] != 0:
        return res["errno"]
    fd = res["r1"]
    w = sys_call("write", fd, val, len(val))
    sys_call("close", fd)
    return w["errno"]


def _show():
    print(sprintf("%-40s %-6s %s", "sysctl", "value", "meaning"))
    print(sprintf("%-40s %-6s %s", "------", "-----", "-------"))
    for ctl in CTLS:
        path = _path(ctl["key"])
        val = read_file(path, default="?").strip()
        print(sprintf("%-40s %-6s %s", ctl["key"], val or "?", ctl["desc"]))


def _apply(which, dry_run):
    failures = 0
    for ctl in CTLS:
        value = ctl[which]
        if not value:
            print("  [*] %s: skipping (no %s value on record)" % (ctl["key"], which))
            continue
        if dry_run:
            print("  [dry-run] %s = %s" % (ctl["key"], value))
            continue
        errno = _write(_path(ctl["key"]), value)
        if errno != 0:
            print("  [!] %s = %s failed (errno=%d)" % (ctl["key"], value, errno))
            failures += 1
        else:
            print("  [+] %s = %s" % (ctl["key"], value))
    return failures


def main(*args):
    action = "show"
    name = ""
    value = ""
    dry_run = False
    if args and args[0]:
        action = str_lower(args[0].strip())
    if len(args) > 1 and args[1]:
        name = args[1].strip()
    if len(args) > 2 and args[2]:
        value = args[2].strip()
    if len(args) > 3 and args[3]:
        dry_run = _is_true(args[3])

    if action == "show":
        _show()
        return "OK"
    if action == "blind":
        print("[*] restricting EDR information sources%s" % (" (dry-run)" if dry_run else ""))
        _apply("blind", dry_run)
        return "OK"
    if action == "open":
        print("[*] restoring permissive sysctls%s" % (" (dry-run)" if dry_run else ""))
        _apply("open", dry_run)
        print("[*] note: modules_disabled=1, once set, is irreversible without a reboot")
        return "OK"
    if action == "set":
        if not name or not value:
            print("[!] set requires --name and --value")
            return "ERROR: name and value required"
        print("[*] setting %s = %s" % (name, value))
        if dry_run:
            return "OK"
        errno = _write(_path(name), value)
        if errno != 0:
            print("[!] write failed (errno=%d; root/CAP_SYS_ADMIN required)" % errno)
            return "ERROR: errno=%d" % errno
        print("[+] %s = %s" % (name, read_file(_path(name), default="?").strip()))
        return "OK"
    print("[!] unknown action: %s" % action)
    return "ERROR: unknown action"
