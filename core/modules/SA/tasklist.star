# Starlark implementation of tasklist/entry.c

def pad(text, width):
    text = str(text)
    if len(text) >= width:
        return text
    return text + " " * (width - len(text))

def read_uint32(addr, offset):
    d = win_read_mem(addr + offset, 4)
    return d[0] | (d[1] << 8) | (d[2] << 16) | (d[3] << 24)

def read_wstring(ptr, max_len=256):
    if ptr == 0:
        return ""
    result = ""
    for i in range(max_len):
        data = win_read_mem(ptr + i * 2, 2)
        c = data[0] | (data[1] << 8)
        if c == 0:
            break
        result += chr(c)
    return result

def write_byte(addr, offset, val):
    win_call("msvcrt.dll", "memset", addr + offset, val & 0xFF, 1)

def write_uint32(addr, offset, val):
    write_byte(addr, offset, val & 0xFF)
    write_byte(addr, offset + 1, (val >> 8) & 0xFF)
    write_byte(addr, offset + 2, (val >> 16) & 0xFF)
    write_byte(addr, offset + 3, (val >> 24) & 0xFF)

def tasklist():
    TH32CS_SNAPPROCESS = 0x00000002
    h_snap = win_call("kernel32.dll", "CreateToolhelp32Snapshot", TH32CS_SNAPPROCESS, 0)["r1"]
    if h_snap == 0 or h_snap == 0xFFFFFFFFFFFFFFFF:
        print("[-] CreateToolhelp32Snapshot failed")
        return "Fail"

    # PROCESSENTRY32W size (x64) is 560 bytes
    entry = win_alloc(560)
    write_uint32(entry, 0, 560)

    print("%s %s %s %s" % (pad("Image Name", 32), pad("PID", 10), pad("PPID", 10), pad("Threads", 10)))
    print("================================ ========== ========== ==========")

    res = win_call("kernel32.dll", "Process32FirstW", h_snap, entry)
    for _ in range(2048):
        if res["r1"] == 0:
            break
        pid = read_uint32(entry, 8)
        cnt_threads = read_uint32(entry, 20)
        ppid = read_uint32(entry, 24)
        exe_name = read_wstring(entry + 44)

        print("%s %s %s %s" % (pad(exe_name, 32), pad(str(pid), 10), pad(str(ppid), 10), pad(str(cnt_threads), 10)))

        res = win_call("kernel32.dll", "Process32NextW", h_snap, entry)

    win_free(entry)
    win_call("kernel32.dll", "CloseHandle", h_snap)
    return "OK"

def main(*args):
    return tasklist()

main()
