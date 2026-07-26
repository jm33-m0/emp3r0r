# Starlark translation of get-netsession2/entry.c


def net_sessions_2(hostname=None, resolve_method=1):
    server_ptr = utf16_ptr(hostname) if hostname else 0
    buf_ptr = win_alloc(8)
    read_ptr_mem = win_alloc(4)
    total_ptr_mem = win_alloc(4)
    resume_ptr = win_alloc(4)
    write_uint32(resume_ptr, 0, 0)

    MAX_PREFERRED_LENGTH = 0xFFFFFFFF

    print("[*] Enumerating sessions for system: %s" % (hostname if hostname else "Local Host"))
    print("[*] Resolving client IPs to hostnames using NetWkstaGetInfo")

    res = win_call("netapi32.dll", "NetSessionEnum", server_ptr, 0, 0, 10, buf_ptr, MAX_PREFERRED_LENGTH, read_ptr_mem, total_ptr_mem, resume_ptr)
    if server_ptr: win_free(server_ptr)

    stat = res["r1"]
    total_count = 0
    if stat == 0 or stat == 234:
        buf = read_ptr(buf_ptr, 0)
        count = read_uint32(read_ptr_mem, 0)

        for i in range(count):
            entry_addr = buf + i * 32
            cname = read_wstring(read_ptr(entry_addr, 0))
            uname = read_wstring(read_ptr(entry_addr, 8))
            time_val = read_uint32(entry_addr, 16)
            idle_val = read_uint32(entry_addr, 20)

            print("---------------Session--------------")
            print("Client: %s" % cname)

            # Query NetWkstaGetInfo for client workstation info
            clean_cname = cname.lstrip("\\")
            cname_ptr = utf16_ptr(clean_cname)
            wksta_buf_ptr = win_alloc(8)

            stat_wksta = win_call("netapi32.dll", "NetWkstaGetInfo", cname_ptr, 100, wksta_buf_ptr)
            win_free(cname_ptr)

            if stat_wksta["r1"] == 0:
                p_wksta = read_ptr(wksta_buf_ptr, 0)
                comp_name = read_wstring(read_ptr(p_wksta, 8))
                comp_dom = read_wstring(read_ptr(p_wksta, 16))
                print("ComputerName:   %s" % comp_name)
                print("ComputerDomain: %s" % comp_dom)
                win_call("netapi32.dll", "NetApiBufferFree", p_wksta)
            else:
                print("ComputerName:   NetWkstaGetInfo Failed; status %d" % stat_wksta["r1"])

            win_free(wksta_buf_ptr)

            print("User:   %s" % uname)
            print("Active: %d" % time_val)
            print("Idle:   %d" % idle_val)
            print("-------------End Session------------\n")
            total_count += 1

        if buf != 0:
            win_call("netapi32.dll", "NetApiBufferFree", buf)

    win_free(buf_ptr)
    win_free(read_ptr_mem)
    win_free(total_ptr_mem)
    win_free(resume_ptr)

    print("\nTotal of %d entries enumerated" % total_count)
    return "OK"

def main(*args):
    host = args[0] if len(args) > 0 and args[0] else None
    return net_sessions_2(host)

