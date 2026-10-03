# lkm_unload - list, inspect and unload kernel modules.
#
# Ported to Starlark from Furtex's edrs/kmod_unload.c.
# Upstream project: https://github.com/MatheuZSecurity/Furtex (MIT License,
# Copyright (c) 2026 MatheuZ). See README.md in this directory for attribution.
#
# delete_module(2) is called directly. Unloading a module removes any
# LSM/kprobe/ftrace hooks it registered; the force flag maps to O_TRUNC, which
# can panic if the module is still executing. Unloading needs CAP_SYS_MODULE.

O_NONBLOCK = 2048
O_TRUNC = 512

EDR_PATTERNS = [
    "edr_lsm_hook", "edr_kal", "edr_nf", "edr_delta", "edr_daemon_d",
    "edr_d_", "edr_e_", "edr_sensor_e", "edr_epsilon", "edr_theta",
    "edr_endpoint_t", "wazuh", "ossec", "sysdig", "scap",
]


def _is_true(s):
    return str_lower(s) in ("true", "1", "yes", "on")


def _is_edr(name):
    for pat in EDR_PATTERNS:
        if str_contains(name, pat):
            return True
    return False


def _list():
    data = read_file("/proc/modules", default="")
    if not data:
        print("[!] /proc/modules not readable")
        return 0
    print(sprintf("  %-32s %-8s %-6s %s", "name", "size", "refcnt", "state"))
    count = 0
    for line in data.splitlines():
        fields = line.split()
        if len(fields) < 3:
            continue
        name = fields[0]
        size = fields[1]
        refcnt = fields[2]
        state = fields[4] if len(fields) > 4 else "?"
        tag = "  <-- EDR" if _is_edr(name) else ""
        print(sprintf("  %-32s %-8s %-6s %s%s", name, size, refcnt, state, tag))
        count += 1
    return count


def _hunt():
    data = read_file("/proc/modules", default="")
    if not data:
        print("[!] /proc/modules not readable")
        return "ERROR: no modules"
    found = 0
    print("[*] scanning for known EDR modules")
    for line in data.splitlines():
        fields = line.split()
        if len(fields) < 3:
            continue
        if _is_edr(fields[0]):
            print(sprintf("  [!] %-32s refcnt=%s state=%s", fields[0], fields[2], fields[4] if len(fields) > 4 else "?"))
            found += 1
    if found == 0:
        print("  [*] none found")
    return "OK"


def _info(name):
    if not name:
        print("[!] info requires --name")
        return "ERROR: name required"
    base = "/sys/module/" + name
    if not exists(base):
        print(sprintf("[!] module %s not loaded", name))
        return "ERROR: not loaded"
    for field in ("version", "refcnt", "srcversion"):
        val = read_file(sprintf("%s/%s", base, field), default="").strip()
        if val:
            print(sprintf("  %-11s %s", field + ":", val))
    holders = list_dir(base + "/holders")
    print(sprintf("  %-11s %s", "holders:", " ".join(holders) if holders else "(none)"))
    print(sprintf("[*] unloading %s removes the ftrace/kprobe hooks it registered", name))
    return "OK"


def _unload(name, force):
    if not name:
        print("[!] unload requires --name")
        return "ERROR: name required"
    if not has_cap("CAP_SYS_MODULE"):
        # delete_module always requires CAP_SYS_MODULE; report the missing
        # capability instead of a generic EPERM from the syscall.
        print(sprintf("[!] missing CAP_SYS_MODULE; skipping delete_module(%s)", name))
        return "OK"
    flags = O_NONBLOCK | O_TRUNC if force else O_NONBLOCK
    print(sprintf("[*] delete_module(%s, flags=%d)%s", name, flags, " FORCE" if force else ""))
    res = sys_call("delete_module", name, flags)
    errno = res["errno"]
    if errno == 0:
        print(sprintf("[+] module %s unloaded", name))
        return "OK"
    hints = {
        16: "EBUSY: module in use; freeze the EDR first or retry with --force",
        11: "EAGAIN: module busy - retry after freezing the EDR",
        1: "EPERM: need CAP_SYS_MODULE (root)",
        2: "ENOENT: module not loaded",
    }
    hint = hints.get(errno, "")
    print(sprintf("[!] delete_module failed (errno=%d) %s", errno, hint))
    return sprintf("ERROR: errno=%d", errno)


def main(*args):
    action = "list"
    name = ""
    force = False
    if args and args[0]:
        action = str_lower(args[0].strip())
    if len(args) > 1 and args[1]:
        name = args[1].strip()
    if len(args) > 2 and args[2]:
        force = _is_true(args[2])

    if action == "list":
        n = _list()
        print(sprintf("[*] %d module(s)", n))
        return "OK"
    if action == "hunt":
        return _hunt()
    if action == "info":
        return _info(name)
    if action == "unload":
        return _unload(name, force)
    print(sprintf("[!] unknown action: %s", action))
    return "ERROR: unknown action"
