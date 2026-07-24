# Starlark translation of SePrivEnable() from priv_windows.go
#
# func SePrivEnable(s string) error {
#     var tokenHandle windows.Token
#     thsHandle := windows.CurrentProcess()
#     windows.OpenProcessToken(thsHandle, windows.TOKEN_ADJUST_PRIVILEGES, &tokenHandle)
#     var luid windows.LUID
#     err := windows.LookupPrivilegeValue(nil, windows.StringToUTF16Ptr(s), &luid)
#     privs := windows.Tokenprivileges{}
#     privs.PrivilegeCount = 1
#     privs.Privileges[0].Luid = luid
#     privs.Privileges[0].Attributes = windows.SE_PRIVILEGE_ENABLED
#     err = windows.AdjustTokenPrivileges(tokenHandle, false, &privs, 0, nil, nil)
# }
#
# Parameters: args[0] = privilege name (e.g. "SeDebugPrivilege")

# ── Windows constants (mirrors priv_windows.go) ───────────────────────────────
TOKEN_ADJUST_PRIVILEGES = 0x0020  # windows.TOKEN_ADJUST_PRIVILEGES
SE_PRIVILEGE_ENABLED = 0x00000002  # windows.SE_PRIVILEGE_ENABLED


# ── Memory helpers ────────────────────────────────────────────────────────────
def read_uint32(addr, offset):
    d = win_read_mem(addr + offset, 4)
    return d[0] | (d[1] << 8) | (d[2] << 16) | (d[3] << 24)


def read_ptr(addr, offset):
    d = win_read_mem(addr + offset, 8)
    return (
        d[0]
        | (d[1] << 8)
        | (d[2] << 16)
        | (d[3] << 24)
        | (d[4] << 32)
        | (d[5] << 40)
        | (d[6] << 48)
        | (d[7] << 56)
    )


def write_byte(addr, offset, val):
    win_call("msvcrt.dll", "memset", addr + offset, val & 0xFF, 1)


def write_uint32(addr, offset, val):
    write_byte(addr, offset, val & 0xFF)
    write_byte(addr, offset + 1, (val >> 8) & 0xFF)
    write_byte(addr, offset + 2, (val >> 16) & 0xFF)
    write_byte(addr, offset + 3, (val >> 24) & 0xFF)


def utf16_ptr(s):
    """Allocate and fill a null-terminated UTF-16LE string (windows.StringToUTF16Ptr)."""
    p = win_alloc((len(s) + 1) * 2)
    for i in range(len(s)):
        c = ord(s[i : i + 1])
        write_byte(p, i * 2, c & 0xFF)
        write_byte(p, i * 2 + 1, (c >> 8) & 0xFF)
    write_byte(p, len(s) * 2, 0)
    write_byte(p, len(s) * 2 + 1, 0)
    return p


# ── SePrivEnable ──────────────────────────────────────────────────────────────
def SePrivEnable(s):
    # var tokenHandle windows.Token
    tokenHandle_ptr = win_alloc(8)

    # thsHandle := windows.CurrentProcess()
    thsHandle = win_call("kernel32.dll", "GetCurrentProcess")["r1"]

    # windows.OpenProcessToken(thsHandle, windows.TOKEN_ADJUST_PRIVILEGES, &tokenHandle)
    win_call(
        "advapi32.dll",
        "OpenProcessToken",
        thsHandle,
        TOKEN_ADJUST_PRIVILEGES,
        tokenHandle_ptr,
    )

    tokenHandle = read_ptr(tokenHandle_ptr, 0)
    win_free(tokenHandle_ptr)

    # var luid windows.LUID  (8 bytes: LowPart DWORD + HighPart LONG)
    luid_ptr = win_alloc(8)

    # privStr := windows.StringToUTF16Ptr(s)
    privStr = utf16_ptr(s)

    # err := windows.LookupPrivilegeValue(nil, windows.StringToUTF16Ptr(s), &luid)
    res = win_call("advapi32.dll", "LookupPrivilegeValueW", 0, privStr, luid_ptr)
    win_free(privStr)
    if res["r1"] == 0:
        win_free(luid_ptr)
        win_call("kernel32.dll", "CloseHandle", tokenHandle)
        print("[-] LookupPrivilegeValueW failed for: " + s)
        return False

    # privs := windows.Tokenprivileges{}
    # Layout: PrivilegeCount(4) + pad(4) + Luid(8) + Attributes(4) = 24 bytes
    privs = win_alloc(24)

    # privs.PrivilegeCount = 1
    write_uint32(privs, 0, 1)
    write_uint32(privs, 4, 0)  # pad

    # privs.Privileges[0].Luid = luid
    luid_lo = read_uint32(luid_ptr, 0)
    luid_hi = read_uint32(luid_ptr, 4)
    write_uint32(privs, 8, luid_lo)
    write_uint32(privs, 12, luid_hi)
    win_free(luid_ptr)

    # privs.Privileges[0].Attributes = windows.SE_PRIVILEGE_ENABLED
    write_uint32(privs, 16, SE_PRIVILEGE_ENABLED)

    # err = windows.AdjustTokenPrivileges(tokenHandle, false, &privs, 0, nil, nil)
    res = win_call(
        "advapi32.dll", "AdjustTokenPrivileges", tokenHandle, 0, privs, 0, 0, 0
    )

    win_free(privs)
    win_call("kernel32.dll", "CloseHandle", tokenHandle)

    if res["r1"] == 0:
        print("[-] AdjustTokenPrivileges failed for: " + s)
        return False

    last_err = win_call("kernel32.dll", "GetLastError")["r1"]
    if last_err == 1300:  # ERROR_NOT_ALL_ASSIGNED
        print("[-] Privilege not held, cannot enable: " + s)
        return False

    print("[+] Privilege enabled: " + s)
    return True


def main(*args):
    s = args[0] if len(args) > 0 else ""
    if not s:
        print("[-] Usage: enablepriv <privilege_name>")
        print(
            "    e.g.  SeDebugPrivilege, SeImpersonatePrivilege, SeAssignPrimaryTokenPrivilege"
        )
        return
    SePrivEnable(s)


main()
