# Starlark translation of get-netsession/entry.c

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

def get_netsession(server=None):
    server_ptr = utf16_ptr(server) if server else 0
    buf_ptr = win_alloc(8)
    read_ptr_mem = win_alloc(4)
    total_ptr_mem = win_alloc(4)
    resume_ptr = win_alloc(4)
    write_uint32(resume_ptr, 0, 0)

    MAX_PREFERRED_LENGTH = 0xFFFFFFFF

    res = win_call("netapi32.dll", "NetSessionEnum", server_ptr, 0, 0, 10, buf_ptr, MAX_PREFERRED_LENGTH, read_ptr_mem, total_ptr_mem, resume_ptr)
    if server_ptr: win_free(server_ptr)

    stat = res["r1"]
    if stat == 0 or stat == 234:
        buf = read_ptr(buf_ptr, 0)
        count = read_uint32(read_ptr_mem, 0)

        print("Network Sessions on %s (%d sessions):" % (server if server else "Local Host", count))
        print("===========================================================================")

        # SESSION_INFO_10 struct on x64 is 32 bytes: cname(0), username(8), time(16), idle(20)
        for i in range(count):
            entry_addr = buf + i * 32
            cname = read_wstring(read_ptr(entry_addr, 0))
            uname = read_wstring(read_ptr(entry_addr, 8))
            time_val = read_uint32(entry_addr, 16)
            idle_val = read_uint32(entry_addr, 20)
            print("  - Computer: %s | User: %s | Active Time: %ds | Idle Time: %ds" % (cname, uname, time_val, idle_val))

        if buf != 0:
            win_call("netapi32.dll", "NetApiBufferFree", buf)
    else:
        print("[-] NetSessionEnum failed: status %d" % stat)

    win_free(buf_ptr)
    win_free(read_ptr_mem)
    win_free(total_ptr_mem)
    win_free(resume_ptr)
    return "OK"

def main(*args):
    server = args[0] if len(args) > 0 and args[0] else None
    return get_netsession(server)

main()
