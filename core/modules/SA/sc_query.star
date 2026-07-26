# Starlark implementation of sc_enum / sc_query / sc_qc

def pad(text, width):
    text = str(text)
    if len(text) >= width:
        return text
    return text + " " * (width - len(text))

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

def get_state_string(state):
    states = {
        1: "STOPPED",
        2: "START_PENDING",
        3: "STOP_PENDING",
        4: "RUNNING",
        5: "CONTINUE_PENDING",
        6: "PAUSE_PENDING",
        7: "PAUSED",
    }
    return states.get(state, "UNKNOWN")

def enumerate_services():
    SC_MANAGER_CONNECT = 0x0001
    SC_MANAGER_ENUMERATE_SERVICE = 0x0004
    SC_ENUM_PROCESS_INFO = 0
    SERVICE_WIN32 = 0x00000030
    SERVICE_STATE_ALL = 0x00000003

    sc_manager = win_call("advapi32.dll", "OpenSCManagerW", 0, 0, SC_MANAGER_CONNECT | SC_MANAGER_ENUMERATE_SERVICE)["r1"]
    if sc_manager == 0:
        print("[-] OpenSCManagerW failed")
        return "OK"

    bytes_needed = win_alloc(4)
    services_returned = win_alloc(4)
    resume_handle = win_alloc(4)

    win_call(
        "advapi32.dll",
        "EnumServicesStatusExW",
        sc_manager,
        SC_ENUM_PROCESS_INFO,
        SERVICE_WIN32,
        SERVICE_STATE_ALL,
        0,
        0,
        bytes_needed,
        services_returned,
        resume_handle,
        0,
    )

    needed = read_uint32(bytes_needed, 0)
    if needed == 0:
        win_free(bytes_needed)
        win_free(services_returned)
        win_free(resume_handle)
        win_call("advapi32.dll", "CloseServiceHandle", sc_manager)
        print("[-] EnumServicesStatusExW failed to determine buffer size")
        return "OK"

    buf = win_alloc(needed)
    res = win_call(
        "advapi32.dll",
        "EnumServicesStatusExW",
        sc_manager,
        SC_ENUM_PROCESS_INFO,
        SERVICE_WIN32,
        SERVICE_STATE_ALL,
        buf,
        needed,
        bytes_needed,
        services_returned,
        resume_handle,
        0,
    )

    if res["r1"] != 0:
        count = read_uint32(services_returned, 0)
        print("SERVICE_NAME                                 DISPLAY_NAME                                 STATE      PID")
        print("============================================ ============================================ ========== ======")

        # ENUM_SERVICE_STATUS_PROCESSW struct size on x64 is 56 bytes:
        # lpServiceName(0,8), lpDisplayName(8,8), ServiceStatusProcess(16,36)
        # ServiceStatusProcess offsets: dwServiceType(16), dwCurrentState(20), ..., dwProcessId(44)
        for i in range(count):
            entry_addr = buf + i * 56
            svc_name = read_wstring(read_ptr(entry_addr, 0))
            display_name = read_wstring(read_ptr(entry_addr, 8))
            state = read_uint32(entry_addr, 20)
            pid = read_uint32(entry_addr, 44)

            print("%s %s %s %s" % (pad(svc_name, 44), pad(display_name, 44), pad(get_state_string(state), 10), str(pid)))

    win_free(buf)
    win_free(bytes_needed)
    win_free(services_returned)
    win_free(resume_handle)
    win_call("advapi32.dll", "CloseServiceHandle", sc_manager)
    return "OK"

def main(*args):
    return enumerate_services()

