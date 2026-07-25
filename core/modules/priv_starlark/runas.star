# Starlark translation of RunAs() from priv_windows.go
#
# func RunAs(username, domain, password, program, args string, show int, netonly bool) error {
#     u, _ := windows.UTF16PtrFromString(username)
#     d, _ := windows.UTF16PtrFromString(domain)
#     p, _ := windows.UTF16PtrFromString(password)
#     prog, _ := windows.UTF16PtrFromString(program)
#     var cmd *uint16
#     if len(args) > 0 {
#         cmd, _ = windows.UTF16PtrFromString(fmt.Sprintf("%s %s", program, args))
#     }
#     var e *uint16        // env = nil (inherit)
#     var di *uint16       // currentDirectory = nil (inherit)
#     si := &syscalls.StartupInfoEx{
#         StartupInfo: windows.StartupInfo{
#             Flags:      windows.STARTF_USESHOWWINDOW,
#             ShowWindow: uint16(show),
#         },
#     }
#     pi := &windows.ProcessInformation{}
#     var logonFlags uint32 = 0
#     if netonly { logonFlags = 2 }  // LOGON_NETCREDENTIALS_ONLY
#     err = syscalls.CreateProcessWithLogonW(u, d, p, logonFlags, prog, cmd, 0, e, di, si, pi)
# }
#
# Parameters:
#   args[0]  username  (string)
#   args[1]  domain    (string)
#   args[2]  password  (string)
#   args[3]  program   (string) – full executable path
#   args[4]  prog_args (string) – extra arguments (may be empty)
#   args[5]  show      (int)    – ShowWindow flag
#   args[6]  netonly   (bool)

# ── Windows constants ─────────────────────────────────────────────────────────
STARTF_USESHOWWINDOW = 0x00000001  # windows.STARTF_USESHOWWINDOW
LOGON_NETCREDENTIALS_ONLY = 2  # from Go source comment


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


def write_uint16(addr, offset, val):
    write_byte(addr, offset, val & 0xFF)
    write_byte(addr, offset + 1, (val >> 8) & 0xFF)


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


# ── RunAs ─────────────────────────────────────────────────────────────────────
def RunAs(username, domain, password, program, extra_args, show, netonly):
    # u, _ := windows.UTF16PtrFromString(username)
    u = utf16_ptr(username)
    # d, _ := windows.UTF16PtrFromString(domain)
    d = utf16_ptr(domain)
    # p, _ := windows.UTF16PtrFromString(password)
    p = utf16_ptr(password)
    # prog, _ := windows.UTF16PtrFromString(program)
    prog = utf16_ptr(program)

    # var cmd *uint16
    # if len(args) > 0 { cmd, _ = windows.UTF16PtrFromString(fmt.Sprintf("%s %s", program, args)) }
    cmd = 0
    if len(extra_args) > 0:
        cmd = utf16_ptr(program + " " + extra_args)

    # var e *uint16   (env = nil, inherit)
    e = 0
    # var di *uint16  (currentDirectory = nil, inherit)
    di = 0

    # si := &syscalls.StartupInfoEx{ StartupInfo: windows.StartupInfo{...} }
    # windows.StartupInfo layout (x64, 104 bytes):
    #   cb(0,4) lpReserved(8,8) lpDesktop(16,8) lpTitle(24,8)
    #   dwX(32,4) dwY(36,4) dwXSize(40,4) dwYSize(44,4)
    #   dwXCountChars(48,4) dwYCountChars(52,4) dwFillAttribute(56,4)
    #   dwFlags(60,4) wShowWindow(64,2) cbReserved2(66,2) <pad>(68,4)
    #   lpReserved2(72,8) hStdInput(80,8) hStdOutput(88,8) hStdError(96,8)
    # StartupInfoEx adds lpAttributeList pointer at offset 104 (8 bytes) → total 112 bytes
    si = win_alloc(112)
    write_uint32(si, 0, 112)  # cb = sizeof(STARTUPINFOEX)
    write_uint32(si, 60, STARTF_USESHOWWINDOW)  # dwFlags
    write_uint16(si, 64, show & 0xFFFF)  # wShowWindow

    # pi := &windows.ProcessInformation{}  (24 bytes: hProcess(8)+hThread(8)+PID(4)+TID(4))
    pi = win_alloc(24)

    # var logonFlags uint32 = 0
    # if netonly { logonFlags = 2 }
    logonFlags = LOGON_NETCREDENTIALS_ONLY if netonly else 0

    # err = syscalls.CreateProcessWithLogonW(u, d, p, logonFlags, prog, cmd, 0, e, di, si, pi)
    res = win_call(
        "advapi32.dll",
        "CreateProcessWithLogonW",
        u,
        d,
        p,
        logonFlags,
        prog,
        cmd,
        0,
        e,
        di,
        si,
        pi,
    )

    if res["r1"] == 0:
        err_code = res.get("err_code", 0)
        err_msg = res.get("error", "")
        print("[-] CreateProcessWithLogonW failed. Error %d: %s" % (err_code, err_msg))
    else:
        new_pid = read_uint32(pi, 16)
        new_tid = read_uint32(pi, 20)
        h_proc = read_ptr(pi, 0)
        h_thread = read_ptr(pi, 8)
        print("[+] Process created: PID=%d TID=%d" % (new_pid, new_tid))
        win_call("kernel32.dll", "CloseHandle", h_proc)
        win_call("kernel32.dll", "CloseHandle", h_thread)

    win_free(u)
    win_free(d)
    win_free(p)
    win_free(prog)
    if cmd != 0:
        win_free(cmd)
    win_free(si)
    win_free(pi)


def main(*args):
    username = args[0] if len(args) > 0 else ""
    domain = args[1] if len(args) > 1 else "."
    password = args[2] if len(args) > 2 else ""
    program = args[3] if len(args) > 3 else ""
    prog_args = args[4] if len(args) > 4 else ""
    show = int(args[5]) if len(args) > 5 else 1
    netonly_raw = args[6] if len(args) > 6 else False
    netonly = (
        netonly_raw == True or netonly_raw == 1 or str(netonly_raw).lower() == "true"
    )

    if str(domain).lower() in ("false", "none", ""):
        domain = "."
    if str(prog_args).lower() in ("false", "none"):
        prog_args = ""

    if not username or not program:
        print(
            "[-] Usage: runas <username> <domain> <password> <program> [args] [show] [netonly]"
        )
        return

    print("[*] RunAs: " + domain + "\\" + username + " -> " + program + " " + prog_args)
    RunAs(username, domain, password, program, prog_args, show, netonly)


main()
