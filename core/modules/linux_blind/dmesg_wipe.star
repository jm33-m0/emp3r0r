# dmesg_wipe - read, grep or clear the kernel ring buffer.
#
# Ported to Starlark from Furtex's edrs/dmesg_wipe.c.
# Upstream project: https://github.com/MatheuZSecurity/Furtex (MIT License,
# Copyright (c) 2026 MatheuZ). See README.md in this directory for attribution.
#
# Uses syslog(2) directly (SYSLOG_ACTION_READ_ALL / CLEAR / SIZE_BUFFER); there
# is no libc klogctl dependency. Reading and clearing need CAP_SYSLOG (or root)
# when kernel.dmesg_restrict is set.

AT_FDCWD = -100

SYSLOG_ACTION_READ_ALL = 3
SYSLOG_ACTION_CLEAR = 5
SYSLOG_ACTION_SIZE_BUFFER = 10

READ_CAP = 4 * 1024 * 1024


def _read_all():
    sz = sys_call("syslog", SYSLOG_ACTION_SIZE_BUFFER, 0, 0)
    if sz["errno"] != 0 or sz["r1"] <= 0:
        return None, sz["errno"]
    size = sz["r1"]
    if size > READ_CAP:
        size = READ_CAP
    buf = sys_alloc(size + 1)
    n = sys_call("syslog", SYSLOG_ACTION_READ_ALL, buf, size)
    if n["errno"] != 0 or n["r1"] <= 0:
        sys_free(buf)
        return None, n["errno"]
    data = read_cstring(buf, n["r1"])
    sys_free(buf)
    return data, 0


def main(*args):
    action = "show"
    pattern = ""
    if args and args[0]:
        action = str_lower(args[0].strip())
    if len(args) > 1 and args[1]:
        pattern = args[1]

    if action == "wipe":
        res = sys_call("syslog", SYSLOG_ACTION_CLEAR, 0, 0)
        if res["errno"] != 0:
            print(sprintf("[!] clearing the ring buffer failed (errno=%d; need CAP_SYSLOG/root and dmesg_restrict=0)", res["errno"]))
            return sprintf("ERROR: errno=%d", res["errno"])
        print("[+] kernel ring buffer cleared")
        return "OK"

    data, errno = _read_all()
    if data == None:
        print(sprintf("[!] reading the ring buffer failed (errno=%d; need CAP_SYSLOG/root and dmesg_restrict=0)", errno))
        return sprintf("ERROR: errno=%d", errno)

    if action == "grep":
        if not pattern:
            print("[!] grep requires --pattern")
            return "ERROR: pattern required"
        hits = 0
        for line in data.splitlines():
            if str_contains(line, pattern):
                print(line)
                hits += 1
        print(sprintf("[*] %d matching line(s)", hits))
        return "OK"

    print(data)
    return "OK"
