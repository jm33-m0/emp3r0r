# Starlark implementation of netuser/entry.c

def write_byte(addr, offset, val):
    win_call("msvcrt.dll", "memset", addr + offset, val & 0xFF, 1)

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
    if ptr == 0:
        return ""
    result = ""
    for i in range(512):
        data = win_read_mem(ptr + i * 2, 2)
        c = data[0] | (data[1] << 8)
        if c == 0:
            break
        result += chr(c)
    return result

def utf16_ptr(s):
    if not s:
        return 0
    p = win_alloc((len(s) + 1) * 2)
    for i in range(len(s)):
        c = ord(s[i : i + 1])
        write_byte(p, i * 2, c & 0xFF)
        write_byte(p, i * 2 + 1, (c >> 8) & 0xFF)
    write_byte(p, len(s) * 2, 0)
    write_byte(p, len(s) * 2 + 1, 0)
    return p

def netuserinfo(username, server=None):
    if not username:
        print("[-] Usage: netuser <username> [server]")
        return "Fail"

    user_ptr = utf16_ptr(username)
    server_ptr = utf16_ptr(server) if server else 0
    buf_ptr = win_alloc(8)

    # NetUserGetInfo level 4
    res = win_call("netapi32.dll", "NetUserGetInfo", server_ptr, user_ptr, 4, buf_ptr)

    win_free(user_ptr)
    if server_ptr: win_free(server_ptr)

    if res["r1"] != 0:
        err_code = res.get("err_code", 0)
        err_msg = res.get("error", "")
        win_free(buf_ptr)
        print("Failed to get user info: status %d (Error %d: %s)" % (res["r1"], err_code, err_msg))
        return "Fail"

    p4 = read_ptr(buf_ptr, 0)
    win_free(buf_ptr)

    if p4 == 0:
        print("Failed to get user info: null buffer returned")
        return "Fail"

    name = read_wstring(read_ptr(p4, 0))
    full_name = read_wstring(read_ptr(p4, 16))
    comment = read_wstring(read_ptr(p4, 24))
    flags = read_uint32(p4, 40)
    script_path = read_wstring(read_ptr(p4, 48))
    home_dir = read_wstring(read_ptr(p4, 88))
    profile = read_wstring(read_ptr(p4, 104))
    workstations = read_wstring(read_ptr(p4, 80))

    UF_ACCOUNTDISABLE = 0x0002
    UF_PASSWD_NOTREQD = 0x0020
    UF_PASSWD_CANT_CHANGE = 0x0040

    print("User name:              %s" % name)
    print("Full Name:              %s" % full_name)
    print("User's comment:         %s" % comment)
    print("Flags (account hex):    0x%x" % flags)
    print("Account enabled:        %s" % ("No" if (flags & UF_ACCOUNTDISABLE) else "Yes"))
    print("Password required:      %s" % ("No" if (flags & UF_PASSWD_NOTREQD) else "Yes"))
    print("User may change pw:     %s" % ("No" if (flags & UF_PASSWD_CANT_CHANGE) else "Yes"))
    print("Workstations allowed:   %s" % (workstations if workstations else "ALL"))
    print("Script path:            %s" % script_path)
    print("User profile:           %s" % profile)
    print("Home directory:         %s" % home_dir)

    win_call("netapi32.dll", "NetApiBufferFree", p4)
    return "OK"

def main(*args):
    username = args[0] if len(args) > 0 else ""
    server = args[1] if len(args) > 1 and args[1] and str(args[1]).lower() not in ("false", "none") else None
    return netuserinfo(username, server)

