# Starlark implementation of vssenum/entry.c

def write_byte(addr, offset, val):
    win_call("msvcrt.dll", "memset", addr + offset, val & 0xFF, 1)

def read_uint32(addr, offset):
    d = win_read_mem(addr + offset, 4)
    return d[0] | (d[1] << 8) | (d[2] << 16) | (d[3] << 24)

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

def vssenum(hostname="localhost", sharename="C$"):
    target = "\\\\%s\\%s" % (hostname, sharename)
    target_ptr = utf16_ptr(target)

    GENERIC_READ = 0x80000000
    FILE_SHARE_READ = 1
    FILE_SHARE_WRITE = 2
    FILE_SHARE_DELETE = 4
    OPEN_EXISTING = 3
    FILE_FLAG_BACKUP_SEMANTICS = 0x02000000

    res = win_call(
        "kernel32.dll",
        "CreateFileW",
        target_ptr,
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        0,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS,
        0,
    )
    win_free(target_ptr)

    h_file = res["r1"]
    if h_file == 0 or h_file == 0xFFFFFFFFFFFFFFFF:
        print("[-] Could not open target folder %s for VSS enumeration" % target)
        return "Fail"

    FSCTL_SRV_ENUMERATE_SNAPSHOTS = 0x00144064
    snapshots_buf = win_alloc(16)
    io_status = win_alloc(16)

    res_fs = win_call(
        "ntdll.dll",
        "NtFsControlFile",
        h_file,
        0,
        0,
        0,
        io_status,
        FSCTL_SRV_ENUMERATE_SNAPSHOTS,
        0,
        0,
        snapshots_buf,
        16,
    )

    if res_fs["r1"] == 0:
        vols_returned = read_uint32(snapshots_buf, 4)
        vol_bytes = read_uint32(snapshots_buf, 8)
        win_free(snapshots_buf)

        if vol_bytes > 0:
            full_len = 12 + vol_bytes
            full_buf = win_alloc(full_len)
            res_full = win_call(
                "ntdll.dll",
                "NtFsControlFile",
                h_file,
                0,
                0,
                0,
                io_status,
                FSCTL_SRV_ENUMERATE_SNAPSHOTS,
                0,
                0,
                full_buf,
                full_len,
            )
            if res_full["r1"] == 0:
                print("VSS Snapshots for %s:" % target)
                print("===========================================================================")
                print("Found and enumerated %d snapshots" % vols_returned)

            win_free(full_buf)
    else:
        win_free(snapshots_buf)
        print("[-] NtFsControlFile failed to query VSS snapshots")

    win_free(io_status)
    win_call("kernel32.dll", "CloseHandle", h_file)
    return "OK"

def main(*args):
    host = args[0] if len(args) > 0 else "localhost"
    share = args[1] if len(args) > 1 else "C$"
    return vssenum(host, share)

