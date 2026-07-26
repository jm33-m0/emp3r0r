# Starlark implementation of netshares/entry.c

def pad(text, width):
    text = str(text)
    if len(text) >= width:
        return text
    return text + " " * (width - len(text))

def write_byte(addr, offset, val):
    win_call("msvcrt.dll", "memset", addr + offset, val & 0xFF, 1)

def write_uint32(addr, offset, val):
    write_byte(addr, offset, val & 0xFF)
    write_byte(addr, offset + 1, (val >> 8) & 0xFF)
    write_byte(addr, offset + 2, (val >> 16) & 0xFF)
    write_byte(addr, offset + 3, (val >> 24) & 0xFF)

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

def list_shares(server=None, as_admin=False):
    server_ptr = utf16_ptr(server) if server else 0
    buf_ptr = win_alloc(8)
    entries_ptr = win_alloc(4)
    total_ptr = win_alloc(4)
    resume_ptr = win_alloc(4)
    write_uint32(resume_ptr, 0, 0)

    level = 2 if as_admin else 1
    MAX_PREFERRED_LENGTH = 0xFFFFFFFF

    target_name = server if server else "(Local)"
    if as_admin:
        print("%s %s %s %s" % (pad("Share:", 20), pad("Local Path:", 30), pad("Uses:", 8), "Descriptor:"))
        print("---------------------%s----------------------------------" % target_name)
    else:
        print("%s %s" % (pad("Share:", 20), "Remark:"))
        print("---------------------%s----------------------------------" % target_name)

    res = win_call(
        "netapi32.dll",
        "NetShareEnum",
        server_ptr,
        level,
        buf_ptr,
        MAX_PREFERRED_LENGTH,
        entries_ptr,
        total_ptr,
        resume_ptr,
    )

    if server_ptr != 0:
        win_free(server_ptr)

    stat = res["r1"]
    if stat == 0 or stat == 234: # ERROR_SUCCESS or ERROR_MORE_DATA
        buf = read_ptr(buf_ptr, 0)
        entries = read_uint32(entries_ptr, 0)

        struct_size = 64 if as_admin else 24
        for i in range(entries):
            entry_addr = buf + i * struct_size
            netname = read_wstring(read_ptr(entry_addr, 0))
            remark = read_wstring(read_ptr(entry_addr, 16))

            if as_admin:
                path = read_wstring(read_ptr(entry_addr, 40))
                uses = read_uint32(entry_addr, 32)
                print("%s%s%s %s" % (pad(netname, 20), pad(path, 30), pad(str(uses), 8), remark))
            else:
                print("%s%s" % (pad(netname, 20), remark))

        if buf != 0:
            win_call("netapi32.dll", "NetApiBufferFree", buf)
    else:
        err_code = res.get("err_code", 0)
        err_msg = res.get("error", "")
        print("Unable to list shares: status %d (Error %d: %s)" % (stat, err_code, err_msg))

    win_free(buf_ptr)
    win_free(entries_ptr)
    win_free(total_ptr)
    win_free(resume_ptr)

def main(*args):
    server = args[0] if len(args) > 0 and args[0] and str(args[0]).lower() not in ("false", "none") else None
    as_admin_raw = args[1] if len(args) > 1 else False
    as_admin = as_admin_raw == True or as_admin_raw == 1 or str(as_admin_raw).lower() == "true"
    list_shares(server, as_admin)

