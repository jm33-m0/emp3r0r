# Starlark implementation of netgroup/entry.c

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

def list_domain_groups(domain=None):
    domain_ptr = utf16_ptr(domain) if domain else 0
    buf_ptr = win_alloc(8)
    read_ptr_mem = win_alloc(4)
    total_ptr_mem = win_alloc(4)
    resume_ptr = win_alloc(8)
    write_uint32(resume_ptr, 0, 0)

    MAX_PREFERRED_LENGTH = 0xFFFFFFFF

    res = win_call(
        "netapi32.dll",
        "NetGroupEnum",
        domain_ptr,
        1, # GROUP_INFO_1
        buf_ptr,
        MAX_PREFERRED_LENGTH,
        read_ptr_mem,
        total_ptr_mem,
        resume_ptr,
    )

    if domain_ptr: win_free(domain_ptr)

    stat = res["r1"]
    if stat == 0 or stat == 234:
        buf = read_ptr(buf_ptr, 0)
        count = read_uint32(read_ptr_mem, 0)

        # GROUP_INFO_1 size on x64 is 16 bytes: grpi1_name (0,8), grpi1_comment (8,8)
        for i in range(count):
            entry_addr = buf + i * 16
            name = read_wstring(read_ptr(entry_addr, 0))
            comment = read_wstring(read_ptr(entry_addr, 8))
            print("Name:      %s" % name)
            print("Comment:   %s" % comment)
            print("--------------------------------")

        if buf != 0:
            win_call("netapi32.dll", "NetApiBufferFree", buf)
    else:
        err_code = res.get("err_code", 0)
        err_msg = res.get("error", "")
        print("[-] NetGroupEnum failed: status %d (Error %d: %s)" % (stat, err_code, err_msg))

    win_free(buf_ptr)
    win_free(read_ptr_mem)
    win_free(total_ptr_mem)
    win_free(resume_ptr)
    return "OK"

def list_group_users(group_name, domain=None):
    if not group_name:
        print("[-] Group name required")
        return "Fail"

    domain_ptr = utf16_ptr(domain) if domain else 0
    group_ptr = utf16_ptr(group_name)
    buf_ptr = win_alloc(8)
    read_ptr_mem = win_alloc(4)
    total_ptr_mem = win_alloc(4)
    resume_ptr = win_alloc(8)
    write_uint32(resume_ptr, 0, 0)

    MAX_PREFERRED_LENGTH = 0xFFFFFFFF

    res = win_call(
        "netapi32.dll",
        "NetGroupGetUsers",
        domain_ptr,
        group_ptr,
        0, # GROUP_USERS_INFO_0
        buf_ptr,
        MAX_PREFERRED_LENGTH,
        read_ptr_mem,
        total_ptr_mem,
        resume_ptr,
    )

    if domain_ptr: win_free(domain_ptr)
    win_free(group_ptr)

    stat = res["r1"]
    if stat == 0 or stat == 234:
        buf = read_ptr(buf_ptr, 0)
        count = read_uint32(read_ptr_mem, 0)

        print("Members of Global Group '%s':" % group_name)
        print("--------------------------------")
        for i in range(count):
            member_name_ptr = read_ptr(buf, i * 8)
            member = read_wstring(member_name_ptr)
            print("-- %s" % member)

        if buf != 0:
            win_call("netapi32.dll", "NetApiBufferFree", buf)
    else:
        err_code = res.get("err_code", 0)
        err_msg = res.get("error", "")
        print("[-] NetGroupGetUsers failed: status %d (Error %d: %s)" % (stat, err_code, err_msg))

    win_free(buf_ptr)
    win_free(read_ptr_mem)
    win_free(total_ptr_mem)
    win_free(resume_ptr)
    return "OK"

def main(*args):
    group = args[0] if len(args) > 0 and args[0] and str(args[0]).lower() not in ("false", "none") else None
    domain = args[1] if len(args) > 1 and args[1] and str(args[1]).lower() not in ("false", "none") else None

    if group:
        return list_group_users(group, domain)
    else:
        return list_domain_groups(domain)

