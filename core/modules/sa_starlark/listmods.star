# Starlark implementation of listmods/entry.c and findLoadedModule/entry.c

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

def listmods(pid=0):
    PROCESS_QUERY_INFORMATION = 0x0400
    PROCESS_VM_READ = 0x0010

    target_pid = int(pid) if pid and str(pid) != "0" else win_call("kernel32.dll", "GetCurrentProcessId")["r1"]

    h_proc = win_call("kernel32.dll", "OpenProcess", PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, 0, target_pid)["r1"]
    if h_proc == 0:
        print("[-] OpenProcess failed for PID %d" % target_pid)
        return "Fail"

    # Allocate module array (1024 module pointers = 8192 bytes)
    mods_buf = win_alloc(8192)
    cb_needed_ptr = win_alloc(4)

    res = win_call("psapi.dll", "EnumProcessModules", h_proc, mods_buf, 8192, cb_needed_ptr)
    if res["r1"] == 0:
        win_free(mods_buf)
        win_free(cb_needed_ptr)
        win_call("kernel32.dll", "CloseHandle", h_proc)
        print("[-] EnumProcessModules failed for PID %d" % target_pid)
        return "Fail"

    needed = read_uint32(cb_needed_ptr, 0)
    win_free(cb_needed_ptr)

    count = needed // 8
    print("Loaded modules for PID %d (%d modules):" % (target_pid, count))
    print("===========================================================================")
    print("%s %s" % (pad("Base Address", 18), "Module Path"))
    print("------------------ --------------------------------------------------------")

    name_buf = win_alloc(512)
    for i in range(count):
        h_mod = read_ptr(mods_buf, i * 8)
        if h_mod != 0:
            win_call("psapi.dll", "GetModuleFileNameExW", h_proc, h_mod, name_buf, 255)
            mod_path = read_wstring(name_buf)
            print("0x%016x %s" % (h_mod, mod_path))

    win_free(mods_buf)
    win_free(name_buf)
    win_call("kernel32.dll", "CloseHandle", h_proc)
    return "OK"

def main(*args):
    pid = args[0] if len(args) > 0 else 0
    return listmods(pid)

main()
