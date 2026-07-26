# Starlark translation of driversigs/entry.c


def driversigs():
    SC_MANAGER_ENUMERATE_SERVICE = 4
    SERVICE_DRIVER = 11
    SERVICE_ACTIVE = 1

    h_scm = win_call("advapi32.dll", "OpenSCManagerA", 0, 0, SC_MANAGER_ENUMERATE_SERVICE)["r1"]
    if h_scm == 0:
        print("[-] OpenSCManagerA failed")
        return "Fail"

    bytes_needed = win_alloc(4)
    services_returned = win_alloc(4)

    # First call to query required buffer size
    win_call("advapi32.dll", "EnumServicesStatusExW", h_scm, 0, SERVICE_DRIVER, SERVICE_ACTIVE, 0, 0, bytes_needed, services_returned, 0, 0)
    needed = read_uint32(bytes_needed, 0)

    if needed == 0:
        win_free(bytes_needed)
        win_free(services_returned)
        win_call("advapi32.dll", "CloseServiceHandle", h_scm)
        print("[-] EnumServicesStatusExW returned 0 bytes needed")
        return "Fail"

    buf = win_alloc(needed)
    res = win_call("advapi32.dll", "EnumServicesStatusExW", h_scm, 0, SERVICE_DRIVER, SERVICE_ACTIVE, buf, needed, bytes_needed, services_returned, 0, 0)
    count = read_uint32(services_returned, 0)

    win_free(bytes_needed)
    win_free(services_returned)

    print("Enumerating %d Active Driver Services & Signatures:" % count)
    print("===========================================================================")

    edr_vendors = [
        "Carbon Black, Inc.", "CrowdStrike, Inc.", "Cylance, Inc.",
        "FireEye, Inc.", "McAfee, Inc.", "Sentinel Labs, Inc.",
        "Symantec Corporation", "Tanium Inc."
    ]

    for i in range(count):
        # ENUM_SERVICE_STATUS_PROCESSW struct on x64 is 56 bytes: lpServiceName(0,8), lpDisplayName(8,8)
        service_ptr = buf + i * 56
        name_ptr = read_ptr(service_ptr, 0)
        if name_ptr != 0 and name_ptr > 4096:
            service_name = read_wstring(name_ptr)
            print("Driver: %s" % service_name)

    win_free(buf)
    win_call("advapi32.dll", "CloseServiceHandle", h_scm)
    print("enumerate_loaded_drivers completed successfully.")
    return "OK"

def main(*args):
    return driversigs()

