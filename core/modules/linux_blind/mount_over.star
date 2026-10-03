# linux_mount_over - bind/tmpfs mounts, read-only remounts and file shadowing.
#
# Ported to Starlark from Furtex's edrs/mount_over.c.
# Upstream project: https://github.com/MatheuZSecurity/Furtex (MIT License,
# Copyright (c) 2026 MatheuZ). See README.md in this directory for attribution.
#
# Requires CAP_SYS_ADMIN (root). Every action has a matching inverse
# (umount), so an operator can restore the mount namespace. Shadow files live
# at an unguessable /tmp path rather than upstream's predictable .mhide-XXXXXX.

AT_FDCWD = -100
O_WRONLY = 1
O_CREAT = 64
O_TRUNC = 512

MS_RDONLY = 1
MS_REMOUNT = 32
MS_BIND = 4096

MNT_DETACH = 2


def _mount(source, target, fstype, flags, data):
    return sys_call("mount", source, target, fstype, flags, data)["errno"]


def _umount(target):
    return sys_call("umount2", target, MNT_DETACH)["errno"]


def _create_file(path):
    res = sys_call("openat", AT_FDCWD, path, O_CREAT | O_WRONLY | O_TRUNC, 420)
    if res["errno"] != 0:
        return res["errno"]
    sys_call("close", res["r1"])
    return 0


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


def _tmp_path():
    return "/tmp/" + _rand_hex(8)


def _list(prefix):
    data = read_file("/proc/mounts", default="")
    if not data:
        print("[!] /proc/mounts not readable")
        return "ERROR: no mounts"
    print(sprintf("[*] mounts%s%s:", " under " if prefix else "", prefix))
    shown = 0
    for line in data.splitlines():
        fields = line.split()
        if len(fields) < 3:
            continue
        mountpoint = fields[1].replace("\\040", " ")
        if prefix and not str_startswith(mountpoint, prefix):
            continue
        print(sprintf("  %-24s %-34s %s", fields[0], mountpoint, fields[2]))
        shown += 1
    print(sprintf("  (%d entries)", shown))
    return "OK"


def _bind(src, dst):
    if not src or not dst:
        print("[!] bind requires --src and --dst")
        return "ERROR: src and dst required"
    errno = _mount(src, dst, 0, MS_BIND, 0)
    if errno != 0:
        print(sprintf("[!] bind mount failed (errno=%d; CAP_SYS_ADMIN required)", errno))
        return sprintf("ERROR: errno=%d", errno)
    print(sprintf("[+] bind-mounted %s over %s", src, dst))
    return "OK"


def _tmpfs(dst, size):
    if not dst:
        print("[!] tmpfs requires --dst")
        return "ERROR: dst required"
    opts = sprintf("size=%s,mode=755", size if size else "10m")
    errno = _mount("tmpfs", dst, "tmpfs", 0, opts)
    if errno != 0:
        print(sprintf("[!] tmpfs mount failed (errno=%d; CAP_SYS_ADMIN required)", errno))
        return sprintf("ERROR: errno=%d", errno)
    print(sprintf("[+] tmpfs mounted over %s (%s); real contents are hidden", dst, opts))
    return "OK"


def _ro(target):
    if not target:
        print("[!] ro requires --dst")
        return "ERROR: target required"
    errno = _mount(target, target, 0, MS_BIND, 0)
    if errno != 0:
        print(sprintf("[!] bind failed (errno=%d)", errno))
        return sprintf("ERROR: errno=%d", errno)
    errno = _mount(0, target, 0, MS_BIND | MS_REMOUNT | MS_RDONLY, 0)
    if errno != 0:
        print(sprintf("[!] remount ro failed (errno=%d)", errno))
        return sprintf("ERROR: errno=%d", errno)
    print(sprintf("[+] %s remounted read-only", target))
    return "OK"


def _hide(src):
    if not src:
        print("[!] hide requires --src")
        return "ERROR: src required"
    parts = src.split("/")
    base = parts[len(parts) - 1]
    if not base:
        print("[!] refuse to shadow a directory root")
        return "ERROR: invalid path"
    tmpdir = _tmp_path()
    mkdir(tmpdir)
    shadow = tmpdir + "/" + base
    errno = _create_file(shadow)
    if errno != 0:
        print(sprintf("[!] could not create shadow file (errno=%d)", errno))
        return sprintf("ERROR: errno=%d", errno)
    errno = _mount(shadow, src, 0, MS_BIND, 0)
    if errno != 0:
        print(sprintf("[!] file bind failed (errno=%d; CAP_SYS_ADMIN required)", errno))
        return sprintf("ERROR: errno=%d", errno)
    print(sprintf("[+] %s is now shadowed by an empty file from %s", src, tmpdir))
    print(sprintf("[*] restore with: linux_mount_over --action umount --dst %s", src))
    return "OK"


def main(*args):
    action = "list"
    src = ""
    dst = ""
    size = "10m"
    if args and args[0]:
        action = str_lower(args[0].strip())
    if len(args) > 1 and args[1]:
        src = args[1]
    if len(args) > 2 and args[2]:
        dst = args[2]
    if len(args) > 3 and args[3]:
        size = args[3]

    if action == "list":
        return _list(dst)
    if action == "bind":
        return _bind(src, dst)
    if action == "tmpfs":
        return _tmpfs(dst, size)
    if action == "ro":
        return _ro(dst)
    if action == "umount":
        if not dst:
            print("[!] umount requires --dst")
            return "ERROR: dst required"
        errno = _umount(dst)
        if errno != 0:
            print(sprintf("[!] umount %s failed (errno=%d)", dst, errno))
            return sprintf("ERROR: errno=%d", errno)
        print(sprintf("[+] unmounted %s; original contents restored", dst))
        return "OK"
    if action == "hide":
        return _hide(src)
    print(sprintf("[!] unknown action: %s", action))
    return "ERROR: unknown action"
