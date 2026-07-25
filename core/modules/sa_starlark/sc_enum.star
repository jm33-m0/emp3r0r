# Starlark translation of sc_enum/entry.c


def sc_enum():
    SC_MANAGER_ENUMERATE_SERVICE = 4
    SERVICE_WIN32 = 0x00000030
    SERVICE_STATE_ALL = 3

    h_scm = win_call("advapi32.dll", "OpenSCManagerW", 0, 0, SC_MANAGER_ENUMERATE_SERVICE)["r1"]
    if h_scm == 0:
        print("[-] OpenSCManagerW failed")
        return "OK"

    bytes_needed = win_alloc(4)
    services_returned = win_alloc(4)

    win_call("advapi32.dll", "EnumServicesStatusExW", h_scm, 0, SERVICE_WIN32, SERVICE_STATE_ALL, 0, 0, bytes_needed, services_returned, 0, 0)
    needed = read_uint32(bytes_needed, 0)

    if needed > 0:
        buf = win_alloc(needed)
        res = win_call("advapi32.dll", "EnumServicesStatusExW", h_scm, 0, SERVICE_WIN32, SERVICE_STATE_ALL, buf, needed, bytes_needed, services_returned, 0, 0)
        count = read_uint32(services_returned, 0)

        print("Service Controller Enumeration (%d services):" % count)
        print("===========================================================================")

        states = ["STOPPED", "START_PENDING", "STOP_PENDING", "RUNNING", "CONTINUE_PENDING", "PAUSE_PENDING", "PAUSED"]

        for i in range(count):
            # ENUM_SERVICE_STATUS_PROCESSW struct on x64 is 56 bytes
            entry_addr = buf + i * 56
            name = read_wstring(read_ptr(entry_addr, 0))
            disp = read_wstring(read_ptr(entry_addr, 8))
            state_val = read_uint32(entry_addr, 20)
            state_str = states[state_val - 1] if (0 < state_val) and (state_val <= len(states)) else "UNKNOWN"

            print(sprintf("  - Service: %-30s | State: %-12s | Name: %s", name, state_str, disp))

        win_free(buf)

    win_free(bytes_needed)
    win_free(services_returned)
    win_call("advapi32.dll", "CloseServiceHandle", h_scm)
    return "OK"

def main(*args):
    return sc_enum()

main()
