# Starlark translation of enumLocalSessions/entry.c

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

def enum_local_sessions():
    WTS_CURRENT_SERVER_HANDLE = 0
    wts_info_ptr = win_alloc(8)
    count_ptr = win_alloc(4)

    res = win_call("wtsapi32.dll", "WTSEnumerateSessionsA", WTS_CURRENT_SERVER_HANDLE, 0, 1, wts_info_ptr, count_ptr)
    if res["r1"] == 0:
        win_free(wts_info_ptr)
        win_free(count_ptr)
        print("[-] WTSEnumerateSessionsA failed")
        return "Fail"

    p_info = read_ptr(wts_info_ptr, 0)
    count = read_uint32(count_ptr, 0)

    win_free(wts_info_ptr)
    win_free(count_ptr)

    print("Enumerating sessions for local system (%d entries):" % count)
    print("===========================================================================")

    WTSUserName = 5
    WTSDomainName = 7
    WTSWinStationName = 1

    username_ptr_ptr = win_alloc(8)
    domain_ptr_ptr = win_alloc(8)
    size_ptr = win_alloc(4)

    users_count = 0
    # WTS_SESSION_INFOA struct size on x64: SessionId(0,4), pWinStationName(8,8), State(16,4) -> total struct size 24 bytes
    for i in range(count):
        session_id = read_uint32(p_info + i * 24, 0)
        state = read_uint32(p_info + i * 24, 16)

        res_user = win_call("wtsapi32.dll", "WTSQuerySessionInformationA", WTS_CURRENT_SERVER_HANDLE, session_id, WTSUserName, username_ptr_ptr, size_ptr)
        if res_user["r1"] != 0:
            p_user = read_ptr(username_ptr_ptr, 0)
            user_str = read_astring(p_user)
            if p_user != 0:
                win_call("wtsapi32.dll", "WTSFreeMemory", p_user)

            if len(user_str) > 0 and (state == 0 or state == 4): # WTSActive (0) or WTSDisconnected (4)
                domain_str = ""
                res_dom = win_call("wtsapi32.dll", "WTSQuerySessionInformationA", WTS_CURRENT_SERVER_HANDLE, session_id, WTSDomainName, domain_ptr_ptr, size_ptr)
                if res_dom["r1"] != 0:
                    p_dom = read_ptr(domain_ptr_ptr, 0)
                    domain_str = read_astring(p_dom)
                    if p_dom != 0:
                        win_call("wtsapi32.dll", "WTSFreeMemory", p_dom)

                print("  - [%d] Session: %s\\%s" % (session_id, domain_str, user_str))
                users_count += 1

    win_free(username_ptr_ptr)
    win_free(domain_ptr_ptr)
    win_free(size_ptr)

    if p_info != 0:
        win_call("wtsapi32.dll", "WTSFreeMemory", p_info)

    print("\nTotal of %d entries enumerated" % users_count)
    return "OK"

def main(*args):
    return enum_local_sessions()

main()
