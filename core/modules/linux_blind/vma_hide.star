# linux_vma_hide - reduce the forensic value of an anonymous mapping.
#
# Ported to Starlark from Furtex's edrs/vma_hide.c.
# Upstream project: https://github.com/MatheuZSecurity/Furtex (MIT License,
# Copyright (c) 2026 MatheuZ). See README.md in this directory for attribution.
#
# The upstream `hide` demo maps RWX shellcode and cycles it through PROT_NONE.
# Starlark cannot execute shellcode allocated here, so this port keeps the two
# primitives an operator can actually use on the agent's own memory:
#   dontdump - MADV_DONTDUMP an anonymous mapping so it never lands in a core
#   name     - give it an innocuous VMA name visible in /proc/<pid>/maps

PR_SET_VMA = 0x53564D41
PR_SET_VMA_ANON_NAME = 0
MADV_DONTDUMP = 16
MADV_DODUMP = 17

PAGE = 4096


def _dontdump():
    buf = sys_alloc(PAGE)
    if buf == 0:
        print("[!] sys_alloc failed")
        return "ERROR: alloc"
    res = sys_call("madvise", buf, PAGE, MADV_DONTDUMP)
    if res["errno"] != 0:
        sys_free(buf)
        print("[!] MADV_DONTDUMP failed (errno=%d)" % res["errno"])
        return "ERROR: errno=%d" % res["errno"]
    print("[+] MADV_DONTDUMP set on an anonymous mapping (0x%x, %d bytes)" % (buf, PAGE))
    print("[*] the mapping is excluded from core dumps; MADV_DODUMP would restore it")
    sys_call("madvise", buf, PAGE, MADV_DODUMP)
    sys_free(buf)
    return "OK"


def _name(name):
    if not name:
        name = "[heap]"
    buf = sys_alloc(PAGE)
    if buf == 0:
        print("[!] sys_alloc failed")
        return "ERROR: alloc"
    name_ptr = cstring_ptr(name)
    res = sys_call("prctl", PR_SET_VMA, PR_SET_VMA_ANON_NAME, buf, PAGE, name_ptr)
    sys_free(buf)
    if res["errno"] != 0:
        print("[!] PR_SET_VMA failed (errno=%d)" % res["errno"])
        return "ERROR: errno=%d" % res["errno"]
    print("[+] anonymous mapping named %s" % name)
    return "OK"


def main(*args):
    action = "dontdump"
    name = ""
    if args and args[0]:
        action = str_lower(args[0].strip())
    if len(args) > 1 and args[1]:
        name = args[1]

    if action == "dontdump":
        return _dontdump()
    if action == "name":
        return _name(name)
    print("[!] unknown action: %s" % action)
    return "ERROR: unknown action"
