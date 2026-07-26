# Starlark implementation of netview/entry.c

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

def netview(domain=None):
    domain_ptr = utf16_ptr(domain) if domain else 0
    buf_ptr = win_alloc(8)
    read_ptr_mem = win_alloc(4)
    total_ptr_mem = win_alloc(4)
    resume_ptr = win_alloc(4)
    write_uint32(resume_ptr, 0, 0)

    SV_TYPE_ALL = 0xFFFFFFFF
    MAX_PREFERRED_LENGTH = 0xFFFFFFFF

    res = win_call(
        "netapi32.dll",
        "NetServerEnum",
        0,
        101, # SERVER_INFO_101
        buf_ptr,
        MAX_PREFERRED_LENGTH,
        read_ptr_mem,
        total_ptr_mem,
        SV_TYPE_ALL,
        domain_ptr,
        resume_ptr,
    )

    if domain_ptr: win_free(domain_ptr)

    stat = res["r1"]
    if stat == 0 or stat == 234:
        buf = read_ptr(buf_ptr, 0)
        count = read_uint32(read_ptr_mem, 0)

        print("Domain Computers (%s):" % (domain if domain else "Local Domain"))
        print("----------------------------------------")
        # SERVER_INFO_101 size on x64 is 24 bytes: sv101_platform_id(0), sv101_name(8), sv101_version_major(16), etc.
        for i in range(count):
            entry_addr = buf + i * 24
            name_ptr = read_ptr(entry_addr, 8)
            name = read_wstring(name_ptr)
            print("\\\\%s" % name)

        if buf != 0:
            win_call("netapi32.dll", "NetApiBufferFree", buf)
    else:
        err_code = res.get("err_code", 0)
        err_msg = res.get("error", "")
        print("[-] NetServerEnum failed: status %d (Error %d: %s)" % (stat, err_code, err_msg))

    win_free(buf_ptr)
    win_free(read_ptr_mem)
    win_free(total_ptr_mem)
    win_free(resume_ptr)
    return "OK"

def main(*args):
    domain = args[0] if len(args) > 0 and args[0] and str(args[0]).lower() not in ("false", "none") else None
    return netview(domain)

main()
