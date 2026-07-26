# Starlark implementation of get_password_policy/entry.c

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

def get_password_policy(server=None):
    server_ptr = utf16_ptr(server) if server else 0
    buf_ptr = win_alloc(8)

    # NetUserModalsGet level 0 (USER_MODALS_INFO_0)
    res = win_call("netapi32.dll", "NetUserModalsGet", server_ptr, 0, buf_ptr)
    if server_ptr: win_free(server_ptr)

    if res["r1"] != 0:
        err_code = res.get("err_code", 0)
        err_msg = res.get("error", "")
        win_free(buf_ptr)
        print("[-] NetUserModalsGet failed: status %d (Error %d: %s)" % (res["r1"], err_code, err_msg))
        return "Fail"

    p0 = read_ptr(buf_ptr, 0)
    win_free(buf_ptr)

    if p0 == 0:
        print("[-] Null buffer returned")
        return "Fail"

    min_pw_len = read_uint32(p0, 0)
    max_pw_age = read_uint32(p0, 4)
    min_pw_age = read_uint32(p0, 8)
    force_logoff = read_uint32(p0, 12)
    pw_hist_len = read_uint32(p0, 16)

    max_pw_age_days = max_pw_age // 86400 if max_pw_age != 0xFFFFFFFF else "Never"
    min_pw_age_days = min_pw_age // 86400 if min_pw_age != 0xFFFFFFFF else "0"

    print("Password Policy for %s:" % (server if server else "Local Domain"))
    print("----------------------------------------")
    print("Minimum password length:   %d" % min_pw_len)
    print("Maximum password age:      %s days" % str(max_pw_age_days))
    print("Minimum password age:      %s days" % str(min_pw_age_days))
    print("Password history length:   %d" % pw_hist_len)

    win_call("netapi32.dll", "NetApiBufferFree", p0)
    return "OK"

def main(*args):
    server = args[0] if len(args) > 0 and args[0] and str(args[0]).lower() not in ("false", "none") else None
    return get_password_policy(server)

