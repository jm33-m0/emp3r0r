# linux_time_stomp - set a file's atime/mtime.
#
# Ported to Starlark from Furtex's edrs/time_stomp.c.
# Upstream project: https://github.com/MatheuZSecurity/Furtex (MIT License,
# Copyright (c) 2026 MatheuZ). See README.md in this directory for attribution.
#
# Unlike upstream we cannot cheaply "clone" another file's timestamps: that
# needs struct stat, which is architecture-specific and not exposed through a
# Go builtin. Setting to now/zero/an explicit epoch covers the anti-forensic
# use case without a new API.

# AT_FDCWD and struct timespec constants.
AT_FDCWD = -100


def _set_times(path, sec, nsec):
    # struct timespec times[2] = { atime, mtime }; 2 * (i64 sec + i64 nsec).
    buf = sys_alloc(32)
    write_u64(buf, 0, sec)
    write_u64(buf, 8, nsec)
    write_u64(buf, 16, sec)
    write_u64(buf, 24, nsec)
    res = sys_call("utimensat", AT_FDCWD, path, buf, 0)
    sys_free(buf)
    return res["errno"]


def _now_seconds():
    tv = sys_alloc(16)  # struct timeval { i64 tv_sec; i64 tv_usec; }
    res = sys_call("gettimeofday", tv, 0)
    sec = read_u64(tv, 0)
    sys_free(tv)
    return sec


def main(*args):
    mode = "now"
    path = ""
    epoch = "0"
    if args and args[0]:
        mode = str_lower(args[0].strip())
    if len(args) > 1 and args[1]:
        path = args[1]
    if len(args) > 2 and args[2]:
        epoch = args[2].strip()

    if not path:
        print("[!] no path given")
        return "ERROR: path required"

    if mode == "zero":
        sec = 0
    elif mode == "set":
        sec = int(epoch)
    else:
        mode = "now"
        sec = _now_seconds()

    errno = _set_times(path, sec, 0)
    if errno != 0:
        print("[!] utimensat %s failed (errno=%d)" % (path, errno))
        return "ERROR: utimensat errno=%d" % errno
    print("[+] %s: atime=mtime=%d (%s)" % (path, sec, mode))
    return "OK"
