# Starlark implementation of netuse/entry.c

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

def write_ptr(addr, offset, val):
    write_uint32(addr, offset, val & 0xFFFFFFFF)
    write_uint32(addr, offset + 4, (val >> 32) & 0xFFFFFFFF)

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

def net_use_add(device_name, share_name, password, username, persist=False, privacy=False):
    # NETRESOURCEW layout (x64, 48 bytes):
    # dwScope(0,4), dwType(4,4), dwDisplayType(8,4), dwUsage(12,4),
    # lpLocalName(16,8), lpRemoteName(24,8), lpComment(32,8), lpProvider(40,8)
    nr = win_alloc(48)
    write_uint32(nr, 4, 1)  # RESOURCETYPE_DISK = 1

    p_dev = utf16_ptr(device_name) if device_name else 0
    p_share = utf16_ptr(share_name) if share_name else 0
    p_pass = utf16_ptr(password) if password else 0
    p_user = utf16_ptr(username) if username else 0

    write_ptr(nr, 16, p_dev)
    write_ptr(nr, 24, p_share)

    CONNECT_UPDATE_PROFILE = 0x00000001
    CONNECT_TEMPORARY = 0x00000004
    CONNECT_ENCRYPTED = 0x00008000

    flags = CONNECT_UPDATE_PROFILE if persist else CONNECT_TEMPORARY
    if privacy:
        flags |= CONNECT_ENCRYPTED

    res = win_call("mpr.dll", "WNetAddConnection2W", nr, p_pass, p_user, flags)

    if p_dev: win_free(p_dev)
    if p_share: win_free(p_share)
    if p_pass: win_free(p_pass)
    if p_user: win_free(p_user)
    win_free(nr)

    if res["r1"] == 0:
        print("The command completed successfully.")
        return "OK"
    else:
        err_code = res.get("err_code", 0)
        err_msg = res.get("error", "")
        print("Unable to map share: status %d (Error %d: %s)" % (res["r1"], err_code, err_msg))
        return "Fail"

def net_use_delete(target, persist=False, force=False):
    p_target = utf16_ptr(target) if target else 0
    flags = 1 if persist else 0
    force_val = 1 if force else 0

    res = win_call("mpr.dll", "WNetCancelConnection2W", p_target, flags, force_val)
    if p_target: win_free(p_target)

    if res["r1"] == 0:
        print("%s was deleted successfully." % target)
        return "OK"
    else:
        err_code = res.get("err_code", 0)
        err_msg = res.get("error", "")
        print("Unable to delete share: status %d (Error %d: %s)" % (res["r1"], err_code, err_msg))
        return "Fail"

def net_use_list(device_name=None):
    RESOURCE_CONNECTED = 1
    RESOURCETYPE_ANY = 0
    h_enum_ptr = win_alloc(8)

    res = win_call("mpr.dll", "WNetOpenEnumW", RESOURCE_CONNECTED, RESOURCETYPE_ANY, 0, 0, h_enum_ptr)
    if res["r1"] != 0:
        err_code = res.get("err_code", 0)
        err_msg = res.get("error", "")
        win_free(h_enum_ptr)
        print("WNetOpenEnumW failed with status %d (Error %d: %s)" % (res["r1"], err_code, err_msg))
        return "Fail"

    h_enum = read_ptr(h_enum_ptr, 0)
    win_free(h_enum_ptr)

    buf_size = 16384
    buf = win_alloc(buf_size)
    entries_ptr = win_alloc(4)
    size_ptr = win_alloc(4)

    if not device_name:
        print("%s %s %s %s" % (pad("Status", 12), pad("Local", 8), pad("Remote", 32), "Network"))
        print("-------------------------------------------------------------------------------------------------")

    while True:
        write_uint32(entries_ptr, 0, 0xFFFFFFFF)
        write_uint32(size_ptr, 0, buf_size)

        res_enum = win_call("mpr.dll", "WNetEnumResourceW", h_enum, entries_ptr, buf, size_ptr)
        if res_enum["r1"] != 0:
            break

        count = read_uint32(entries_ptr, 0)
        if count == 0:
            break

        # NETRESOURCEW array iteration (48 bytes per entry)
        for i in range(count):
            entry_addr = buf + i * 48
            local_name = read_wstring(read_ptr(entry_addr, 16))
            remote_name = read_wstring(read_ptr(entry_addr, 24))
            provider = read_wstring(read_ptr(entry_addr, 40))

            if not device_name:
                print("%s %s %s %s" % (pad("OK", 12), pad(local_name, 8), pad(remote_name, 32), provider))
            elif device_name.lower() in (local_name.lower(), remote_name.lower()):
                print("Local name        %s\nRemote name       %s\nNetwork           %s\n" % (local_name, remote_name, provider))

    win_free(buf)
    win_free(entries_ptr)
    win_free(size_ptr)
    win_call("mpr.dll", "WNetCloseEnum", h_enum)
    print("The command completed successfully.")
    return "OK"

def main(*args):
    cmd = args[0] if len(args) > 0 else "list"
    if cmd == "add":
        share = args[1] if len(args) > 1 else ""
        user = args[2] if len(args) > 2 else ""
        password = args[3] if len(args) > 3 else ""
        device = args[4] if len(args) > 4 else ""
        return net_use_add(device, share, password, user)
    elif cmd == "delete":
        target = args[1] if len(args) > 1 else ""
        return net_use_delete(target)
    else:
        device = args[1] if len(args) > 1 and args[1] and str(args[1]).lower() not in ("false", "none") else None
        return net_use_list(device)

main()
