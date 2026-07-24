# Starlark translation of MakeToken() from priv_windows.go
#
# func MakeToken(domain string, username string, password string, logonType uint32) error {
#     var token windows.Token
#     if logonType == 0 { logonType = syscalls.LOGON32_LOGON_NEW_CREDENTIALS }
#     pd, _ := windows.UTF16PtrFromString(domain)
#     pu, _ := windows.UTF16PtrFromString(username)
#     pp, _ := windows.UTF16PtrFromString(password)
#     if logonType == syscalls.LOGON32_LOGON_NEW_CREDENTIALS {
#         err = syscalls.LogonUser(pu, pd, pp, logonType, syscalls.LOGON32_PROVIDER_WINNT50, &token)
#     } else {
#         err = syscalls.LogonUser(pu, pd, pp, logonType, syscalls.LOGON32_PROVIDER_DEFAULT, &token)
#     }
#     err = syscalls.ImpersonateLoggedOnUser(token)
#     CurrentToken = token
# }
#
# Parameters:
#   args[0]  domain      (string)
#   args[1]  username    (string)
#   args[2]  password    (string)
#   args[3]  logon_type  (int, default 9)

# ── Logon constants (mirrors syscalls package) ────────────────────────────────
LOGON32_LOGON_NEW_CREDENTIALS = 9  # syscalls.LOGON32_LOGON_NEW_CREDENTIALS
LOGON32_PROVIDER_DEFAULT = 0  # syscalls.LOGON32_PROVIDER_DEFAULT
LOGON32_PROVIDER_WINNT50 = 3  # syscalls.LOGON32_PROVIDER_WINNT50


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


def read_wstring(ptr):
    result = ""
    off = 0
    for _ in range(512):
        d = win_read_mem(ptr + off, 2)
        c = d[0] | (d[1] << 8)
        if c == 0:
            break
        result += chr(c)
        off += 2
    return result


def write_byte(addr, offset, val):
    win_call("msvcrt.dll", "memset", addr + offset, val & 0xFF, 1)


def write_uint32(addr, offset, val):
    write_byte(addr, offset, val & 0xFF)
    write_byte(addr, offset + 1, (val >> 8) & 0xFF)
    write_byte(addr, offset + 2, (val >> 16) & 0xFF)
    write_byte(addr, offset + 3, (val >> 24) & 0xFF)


def utf16_ptr(s):
    """windows.UTF16PtrFromString equivalent."""
    p = win_alloc((len(s) + 1) * 2)
    for i in range(len(s)):
        c = ord(s[i : i + 1])
        write_byte(p, i * 2, c & 0xFF)
        write_byte(p, i * 2 + 1, (c >> 8) & 0xFF)
    write_byte(p, len(s) * 2, 0)
    write_byte(p, len(s) * 2 + 1, 0)
    return p


# Token owner resolution helper (for confirmation output)
def token_owner_str(h_token):
    TokenUser = 1
    sz_ptr = win_alloc(4)
    win_call("advapi32.dll", "GetTokenInformation", h_token, TokenUser, 0, 0, sz_ptr)
    d = win_read_mem(sz_ptr, 4)
    sz = d[0] | (d[1] << 8) | (d[2] << 16) | (d[3] << 24)
    win_free(sz_ptr)
    if sz == 0:
        return ""
    buf = win_alloc(sz)
    sz_ptr2 = win_alloc(4)
    win_call(
        "advapi32.dll", "GetTokenInformation", h_token, TokenUser, buf, sz, sz_ptr2
    )
    win_free(sz_ptr2)
    sid_ptr = read_ptr(buf, 0)
    cn_ptr = win_alloc(4)
    dn_ptr = win_alloc(4)
    use_ptr = win_alloc(4)
    win_call(
        "advapi32.dll", "LookupAccountSidW", 0, sid_ptr, 0, cn_ptr, 0, dn_ptr, use_ptr
    )
    d = win_read_mem(cn_ptr, 4)
    ns = d[0] | (d[1] << 8) | (d[2] << 16) | (d[3] << 24)
    d = win_read_mem(dn_ptr, 4)
    ds = d[0] | (d[1] << 8) | (d[2] << 16) | (d[3] << 24)
    if ns == 0:
        ns = 256
    if ds == 0:
        ds = 256
    nb = win_alloc(ns * 2)
    db2 = win_alloc(ds * 2)
    win_call(
        "advapi32.dll",
        "LookupAccountSidW",
        0,
        sid_ptr,
        nb,
        cn_ptr,
        db2,
        dn_ptr,
        use_ptr,
    )
    acct = read_wstring(nb)
    dom = read_wstring(db2)
    win_free(cn_ptr)
    win_free(dn_ptr)
    win_free(use_ptr)
    win_free(nb)
    win_free(db2)
    win_free(buf)
    return dom + "\\" + acct


# ── MakeToken ─────────────────────────────────────────────────────────────────
def MakeToken(domain, username, password, logonType):
    # var token windows.Token
    token_ptr = win_alloc(8)

    # if logonType == 0 { logonType = syscalls.LOGON32_LOGON_NEW_CREDENTIALS }
    if logonType == 0:
        logonType = LOGON32_LOGON_NEW_CREDENTIALS

    # pd, _ := windows.UTF16PtrFromString(domain)
    pd = utf16_ptr(domain)
    # pu, _ := windows.UTF16PtrFromString(username)
    pu = utf16_ptr(username)
    # pp, _ := windows.UTF16PtrFromString(password)
    pp = utf16_ptr(password)

    # if logonType == syscalls.LOGON32_LOGON_NEW_CREDENTIALS {
    #     err = syscalls.LogonUser(pu, pd, pp, logonType, syscalls.LOGON32_PROVIDER_WINNT50, &token)
    # } else {
    #     err = syscalls.LogonUser(pu, pd, pp, logonType, syscalls.LOGON32_PROVIDER_DEFAULT, &token)
    # }
    if logonType == LOGON32_LOGON_NEW_CREDENTIALS:
        res = win_call(
            "advapi32.dll",
            "LogonUserW",
            pu,
            pd,
            pp,
            logonType,
            LOGON32_PROVIDER_WINNT50,
            token_ptr,
        )
    else:
        res = win_call(
            "advapi32.dll",
            "LogonUserW",
            pu,
            pd,
            pp,
            logonType,
            LOGON32_PROVIDER_DEFAULT,
            token_ptr,
        )

    win_free(pu)
    win_free(pd)
    win_free(pp)

    if res["r1"] == 0:
        win_free(token_ptr)
        err = win_call("kernel32.dll", "GetLastError")["r1"]
        print("[-] LogonUserW failed. Error: %d" % err)
        return

    token = read_ptr(token_ptr, 0)
    win_free(token_ptr)

    # err = syscalls.ImpersonateLoggedOnUser(token)
    res = win_call("advapi32.dll", "ImpersonateLoggedOnUser", token)
    if res["r1"] == 0:
        err = win_call("kernel32.dll", "GetLastError")["r1"]
        win_call("kernel32.dll", "CloseHandle", token)
        print("[-] ImpersonateLoggedOnUser failed. Error: %d" % err)
        return

    # CurrentToken = token  (resolved via token owner for output)
    owner = token_owner_str(token)
    print("[+] Token created. Impersonating: %s" % owner)
    # Close – the impersonation context persists on the thread even after CloseHandle on the token
    win_call("kernel32.dll", "CloseHandle", token)


def main(*args):
    domain = args[0] if len(args) > 0 else "."
    username = args[1] if len(args) > 1 else ""
    password = args[2] if len(args) > 2 else ""
    logonType = int(args[3]) if len(args) > 3 else 0

    if str(domain).lower() in ("false", "none", ""):
        domain = "."
    if not username:
        print("[-] Usage: maketoken <domain> <username> <password> [logon_type]")
        print("    logon_type: 2=Interactive 3=Network 9=NewCredentials(default)")
        return

    MakeToken(domain, username, password, logonType)


main()
