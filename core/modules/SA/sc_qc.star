# Starlark translation of sc_qc/entry.c

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

def read_astring(ptr):
    if ptr == 0:
        return ""
    result = ""
    for i in range(256):
        data = win_read_mem(ptr + i, 1)
        if data[0] == 0:
            break
        result += chr(data[0])
    return result

def sc_qc(service_name, hostname=None):
    if not service_name:
        print("[-] Usage: sc_qc <service_name> [hostname]")
        return "Fail"

    SC_MANAGER_CONNECT = 1
    GENERIC_READ = 0x80000000

    h_scm = win_call("advapi32.dll", "OpenSCManagerA", 0, 0, SC_MANAGER_CONNECT | GENERIC_READ)["r1"]
    if h_scm == 0:
        print("[-] OpenSCManagerA failed for service %s" % service_name)
        return "Fail"

    # Convert service_name to ASCII ptr
    name_ptr = win_alloc(len(service_name) + 1)
    for i in range(len(service_name)):
        write_byte(name_ptr, i, ord(service_name[i]))
    write_byte(name_ptr, len(service_name), 0)

    h_service = win_call("advapi32.dll", "OpenServiceA", h_scm, name_ptr, GENERIC_READ)["r1"]
    win_free(name_ptr)

    if h_service == 0:
        win_call("advapi32.dll", "CloseServiceHandle", h_scm)
        print("[-] OpenServiceA failed for service %s" % service_name)
        return "Fail"

    bytes_needed = win_alloc(4)
    win_call("advapi32.dll", "QueryServiceConfigA", h_service, 0, 0, bytes_needed)
    needed = read_uint32(bytes_needed, 0)

    if needed > 0:
        config_buf = win_alloc(needed)
        res_cfg = win_call("advapi32.dll", "QueryServiceConfigA", h_service, config_buf, needed, bytes_needed)

        if res_cfg["r1"] != 0:
            # QUERY_SERVICE_CONFIGA on x64: ServiceType(0,4), StartType(4,4), ErrorControl(8,4), BinaryPathName(16,8), LoadOrderGroup(24,8), TagId(32,4), Dependencies(40,8), ServiceStartName(48,8), DisplayName(56,8)
            srv_type = read_uint32(config_buf, 0)
            start_type = read_uint32(config_buf, 4)
            err_control = read_uint32(config_buf, 8)
            bin_path = read_astring(read_ptr(config_buf, 16))
            group = read_astring(read_ptr(config_buf, 24))
            start_name = read_astring(read_ptr(config_buf, 48))
            disp_name = read_astring(read_ptr(config_buf, 56))

            start_types = ["BOOT_DRIVER", "SYSTEM_START_DRIVER", "AUTO_START", "DEMAND_START", "DISABLED"]
            start_str = start_types[start_type] if start_type < len(start_types) else "UNKNOWN"

            print("SERVICE_NAME: %s" % service_name)
            print("        TYPE               : %x" % srv_type)
            print("        START_TYPE         : %d (%s)" % (start_type, start_str))
            print("        ERROR_CONTROL      : %d" % err_control)
            print("        BINARY_PATH_NAME   : %s" % bin_path)
            print("        LOAD_ORDER_GROUP   : %s" % group)
            print("        DISPLAY_NAME       : %s" % disp_name)
            print("        SERVICE_START_NAME : %s" % start_name)

        win_free(config_buf)

    win_free(bytes_needed)
    win_call("advapi32.dll", "CloseServiceHandle", h_service)
    win_call("advapi32.dll", "CloseServiceHandle", h_scm)
    return "OK"

def main(*args):
    service = args[0] if len(args) > 0 else "webclient"
    host = args[1] if len(args) > 1 else None
    return sc_qc(service, host)

