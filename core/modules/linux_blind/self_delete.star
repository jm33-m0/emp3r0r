# linux_self_delete - unlink a running binary from disk.
#
# Ported to Starlark from Furtex's edrs/self_delete.c.
# Upstream project: https://github.com/MatheuZSecurity/Furtex (MIT License,
# Copyright (c) 2026 MatheuZ). See README.md in this directory for attribution.
#
# Only the unlink half is ported. The upstream memfd re-exec path spawns a new
# process via execve, which the agent model forbids: the agent must stay
# resident, so deleting the image from disk without re-exec is the useful part.
# On Linux an open, executing image keeps running after its directory entry is
# removed; /proc/self/exe then reports the "(deleted)" suffix.

AT_FDCWD = -100


def _unlink(path):
    return sys_call("unlinkat", AT_FDCWD, path, 0)["errno"]


def main(*args):
    path = ""
    if args and args[0]:
        path = args[0].strip()
    target = path if path else "/proc/self/exe"

    before = read_link("/proc/self/exe", default="?")
    errno = _unlink(target)
    if errno != 0:
        print(sprintf("[!] unlink %s failed (errno=%d)", target, errno))
        return sprintf("ERROR: errno=%d", errno)

    after = read_link("/proc/self/exe", default="?")
    print(sprintf("[+] unlinked %s", target))
    print(sprintf("[*] /proc/self/exe before: %s", before))
    print(sprintf("[*] /proc/self/exe after:  %s", after))
    print("[*] the process keeps running with no image on disk")
    return "OK"
