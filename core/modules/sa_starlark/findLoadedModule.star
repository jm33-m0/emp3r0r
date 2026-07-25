# Starlark translation of findLoadedModule/entry.c


def find_loaded_module(mod_name="", pid=0):
    PROCESS_QUERY_INFORMATION = 0x0400
    PROCESS_VM_READ = 0x0010

    target_pid = int(pid) if pid and str(pid) != "0" else win_call("kernel32.dll", "GetCurrentProcessId")["r1"]
    h_proc = win_call("kernel32.dll", "OpenProcess", PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, 0, target_pid)["r1"]

    if h_proc == 0:
        target_pid = win_call("kernel32.dll", "GetCurrentProcessId")["r1"]
        h_proc = win_call("kernel32.dll", "OpenProcess", PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, 0, target_pid)["r1"]

    if h_proc == 0:
        print("[-] OpenProcess failed for PID %d" % target_pid)
        return "Fail"

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
    if count > 1024:
        count = 1024
    name_buf = win_alloc(512)
    found = False

    print("Searching for module '%s' in PID %d:" % (mod_name, target_pid))
    print("===========================================================================")

    for i in range(count):
        h_mod = read_ptr(mods_buf, i * 8)
        if h_mod != 0:
            win_call("psapi.dll", "GetModuleFileNameExW", h_proc, h_mod, name_buf, 255)
            path = read_wstring(name_buf)
            if not mod_name or mod_name.lower() in path.lower():
                print("FOUND: %s -> %s" % (sprintf("0x%016x", h_mod), path))
                found = True

    if not found:
        print("[-] Module '%s' not found in process %d" % (mod_name, target_pid))

    win_free(mods_buf)
    win_free(name_buf)
    win_call("kernel32.dll", "CloseHandle", h_proc)
    return "OK"

def main(*args):
    mod_name = args[0] if len(args) > 0 else ""
    pid = args[1] if len(args) > 1 else 0
    return find_loaded_module(mod_name, pid)

main()
