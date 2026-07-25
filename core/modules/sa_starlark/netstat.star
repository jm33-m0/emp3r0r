# Starlark implementation of netstat

def pad(text, width):
    text = str(text)
    if len(text) >= width:
        return text
    return text + " " * (width - len(text))

TcpState = [
    "???",
    "CLOSED",
    "LISTENING",
    "SYN_SENT",
    "SYN_RCVD",
    "ESTABLISHED",
    "FIN_WAIT1",
    "FIN_WAIT2",
    "CLOSE_WAIT",
    "CLOSING",
    "LAST_ACK",
    "TIME_WAIT",
    "DELETE_TCB"
]

def get_ip_host_name(ip_addr):
    p1 = ip_addr & 0xFF
    p2 = (ip_addr >> 8) & 0xFF
    p3 = (ip_addr >> 16) & 0xFF
    p4 = (ip_addr >> 24) & 0xFF
    return "{}.{}.{}.{}".format(p1, p2, p3, p4)

def get_ip6_host_name(addr_bytes):
    parts = []
    for i in range(8):
        b1 = addr_bytes[i*2]
        b2 = addr_bytes[i*2+1]
        val = (b1 << 8) | b2
        parts.append("%x" % val)
    return ":".join(parts)

def get_port_name(port_addr):
    p1 = port_addr & 0xFF
    p2 = (port_addr >> 8) & 0xFF
    return (p1 << 8) | p2

def get_name_by_pid(pid):
    # PROCESS_QUERY_INFORMATION = 0x0400, PROCESS_VM_READ = 0x0010
    hProcess = win_call("kernel32.dll", "OpenProcess", 0x0410, 0, pid)["r1"]
    if hProcess == 0:
        return ""
        
    name_buf = win_alloc(512)
    size_ptr = win_alloc(4)
    win_call("msvcrt.dll", "memset", size_ptr, 0, 4)
    win_call("msvcrt.dll", "memset", size_ptr, 256 & 0xFF, 1)
    win_call("msvcrt.dll", "memset", size_ptr + 1, (256 >> 8) & 0xFF, 1)
    
    # QueryFullProcessImageNameA
    res = win_call("kernel32.dll", "QueryFullProcessImageNameA", hProcess, 0, name_buf, size_ptr)
    
    proc_name = ""
    if res["r1"] != 0:
        length = win_read_mem(size_ptr, 4)
        length = length[0] | (length[1] << 8) | (length[2] << 16) | (length[3] << 24)
        if length > 0:
            bytes_read = win_read_mem(name_buf, length)
            for b in bytes_read:
                proc_name += chr(b)
                
    win_free(name_buf)
    win_free(size_ptr)
    win_call("kernel32.dll", "CloseHandle", hProcess)
    return proc_name

def show_tcp_table():
    # TCP_TABLE_OWNER_PID_ALL = 5
    # AF_INET = 2
    size_ptr = win_alloc(4)
    win_call("msvcrt.dll", "memset", size_ptr, 0, 4)
    
    # GetExtendedTcpTable
    win_call("iphlpapi.dll", "GetExtendedTcpTable", 0, size_ptr, 1, 2, 5, 0)
    
    size_bytes = win_read_mem(size_ptr, 4)
    size = size_bytes[0] | (size_bytes[1] << 8) | (size_bytes[2] << 16) | (size_bytes[3] << 24)
    
    if size == 0:
        win_free(size_ptr)
        return
        
    table_ptr = win_alloc(size)
    res = win_call("iphlpapi.dll", "GetExtendedTcpTable", table_ptr, size_ptr, 1, 2, 5, 0)
    if res["r1"] != 0:
        err_code = res.get("err_code", 0)
        err_msg = res.get("error", "")
        print("GetExtendedTcpTable (TCP) failed with status %d (Error %d: %s)" % (res["r1"], err_code, err_msg))
        win_free(table_ptr)
        win_free(size_ptr)
        return
        
    entries_bytes = win_read_mem(table_ptr, 4)
    entries = entries_bytes[0] | (entries_bytes[1] << 8) | (entries_bytes[2] << 16) | (entries_bytes[3] << 24)
    
    for i in range(entries):
        row_offset = 4 + i * 24
        row_bytes = win_read_mem(table_ptr + row_offset, 24)
        
        dwState = row_bytes[0] | (row_bytes[1] << 8) | (row_bytes[2] << 16) | (row_bytes[3] << 24)
        dwLocalAddr = row_bytes[4] | (row_bytes[5] << 8) | (row_bytes[6] << 16) | (row_bytes[7] << 24)
        dwLocalPort = row_bytes[8] | (row_bytes[9] << 8) | (row_bytes[10] << 16) | (row_bytes[11] << 24)
        dwRemoteAddr = row_bytes[12] | (row_bytes[13] << 8) | (row_bytes[14] << 16) | (row_bytes[15] << 24)
        dwRemotePort = row_bytes[16] | (row_bytes[17] << 8) | (row_bytes[18] << 16) | (row_bytes[19] << 24)
        dwOwningPid = row_bytes[20] | (row_bytes[21] << 8) | (row_bytes[22] << 16) | (row_bytes[23] << 24)
        
        host_ip = get_ip_host_name(dwLocalAddr)
        host_port = get_port_name(dwLocalPort)
        host = "{}:{}".format(host_ip, host_port)
        
        if dwState == 2: # MIB_TCP_STATE_LISTEN
            remote = "*:*"
        else:
            remote_ip = get_ip_host_name(dwRemoteAddr)
            remote_port = get_port_name(dwRemotePort)
            remote = "{}:{}".format(remote_ip, remote_port)
            
        proc_name = get_name_by_pid(dwOwningPid)
        state_str = TcpState[dwState] if dwState < len(TcpState) else "UNKNOWN"
        
        print("  {} {} {} {} {}({})".format(
            pad("TCP", 6),
            pad(host, 48),
            pad(remote, 48),
            pad(state_str, 13),
            proc_name,
            dwOwningPid
        ))
        
    win_free(table_ptr)
    win_free(size_ptr)

def show_tcp6_table():
    # TCP_TABLE_OWNER_PID_ALL = 5
    # AF_INET6 = 23
    size_ptr = win_alloc(4)
    win_call("msvcrt.dll", "memset", size_ptr, 0, 4)
    
    win_call("iphlpapi.dll", "GetExtendedTcpTable", 0, size_ptr, 1, 23, 5, 0)
    
    size_bytes = win_read_mem(size_ptr, 4)
    size = size_bytes[0] | (size_bytes[1] << 8) | (size_bytes[2] << 16) | (size_bytes[3] << 24)
    
    if size == 0:
        win_free(size_ptr)
        return
        
    table_ptr = win_alloc(size)
    res = win_call("iphlpapi.dll", "GetExtendedTcpTable", table_ptr, size_ptr, 1, 23, 5, 0)
    if res["r1"] != 0:
        err_code = res.get("err_code", 0)
        err_msg = res.get("error", "")
        print("GetExtendedTcpTable (TCP6) failed with status %d (Error %d: %s)" % (res["r1"], err_code, err_msg))
        win_free(table_ptr)
        win_free(size_ptr)
        return
        
    entries_bytes = win_read_mem(table_ptr, 4)
    entries = entries_bytes[0] | (entries_bytes[1] << 8) | (entries_bytes[2] << 16) | (entries_bytes[3] << 24)
    
    # MIB_TCP6ROW_OWNER_PID is 56 bytes
    # ucLocalAddr: 16, dwLocalScopeId: 4, dwLocalPort: 4, ucRemoteAddr: 16, dwRemoteScopeId: 4, dwRemotePort: 4, dwState: 4, dwOwningPid: 4
    for i in range(entries):
        row_offset = 4 + i * 56
        row_bytes = win_read_mem(table_ptr + row_offset, 56)
        
        ucLocalAddr = row_bytes[0:16]
        dwLocalPort = row_bytes[20] | (row_bytes[21] << 8) | (row_bytes[22] << 16) | (row_bytes[23] << 24)
        ucRemoteAddr = row_bytes[24:40]
        dwRemotePort = row_bytes[44] | (row_bytes[45] << 8) | (row_bytes[46] << 16) | (row_bytes[47] << 24)
        dwState = row_bytes[48] | (row_bytes[49] << 8) | (row_bytes[50] << 16) | (row_bytes[51] << 24)
        dwOwningPid = row_bytes[52] | (row_bytes[53] << 8) | (row_bytes[54] << 16) | (row_bytes[55] << 24)
        
        host_ip = get_ip6_host_name(ucLocalAddr)
        host_port = get_port_name(dwLocalPort)
        host = "[{}]:{}".format(host_ip, host_port)
        
        if dwState == 2:
            remote = "*:*"
        else:
            remote_ip = get_ip6_host_name(ucRemoteAddr)
            remote_port = get_port_name(dwRemotePort)
            remote = "[{}]:{}".format(remote_ip, remote_port)
            
        proc_name = get_name_by_pid(dwOwningPid)
        state_str = TcpState[dwState] if dwState < len(TcpState) else "UNKNOWN"
        
        print("  {} {} {} {} {}({})".format(
            pad("TCP6", 6),
            pad(host, 48),
            pad(remote, 48),
            pad(state_str, 13),
            proc_name,
            dwOwningPid
        ))
        
    win_free(table_ptr)
    win_free(size_ptr)

def show_udp_table():
    # UDP_TABLE_OWNER_PID = 1
    # AF_INET = 2
    size_ptr = win_alloc(4)
    win_call("msvcrt.dll", "memset", size_ptr, 0, 4)
    
    win_call("iphlpapi.dll", "GetExtendedUdpTable", 0, size_ptr, 1, 2, 1, 0)
    
    size_bytes = win_read_mem(size_ptr, 4)
    size = size_bytes[0] | (size_bytes[1] << 8) | (size_bytes[2] << 16) | (size_bytes[3] << 24)
    
    if size == 0:
        win_free(size_ptr)
        return
        
    table_ptr = win_alloc(size)
    res = win_call("iphlpapi.dll", "GetExtendedUdpTable", table_ptr, size_ptr, 1, 2, 1, 0)
    if res["r1"] != 0:
        err_code = res.get("err_code", 0)
        err_msg = res.get("error", "")
        print("GetExtendedUdpTable (UDP) failed with status %d (Error %d: %s)" % (res["r1"], err_code, err_msg))
        win_free(table_ptr)
        win_free(size_ptr)
        return
        
    entries_bytes = win_read_mem(table_ptr, 4)
    entries = entries_bytes[0] | (entries_bytes[1] << 8) | (entries_bytes[2] << 16) | (entries_bytes[3] << 24)
    
    # MIB_UDPROW_OWNER_PID is 12 bytes
    for i in range(entries):
        row_offset = 4 + i * 12
        row_bytes = win_read_mem(table_ptr + row_offset, 12)
        
        dwLocalAddr = row_bytes[0] | (row_bytes[1] << 8) | (row_bytes[2] << 16) | (row_bytes[3] << 24)
        dwLocalPort = row_bytes[4] | (row_bytes[5] << 8) | (row_bytes[6] << 16) | (row_bytes[7] << 24)
        dwOwningPid = row_bytes[8] | (row_bytes[9] << 8) | (row_bytes[10] << 16) | (row_bytes[11] << 24)
        
        host_ip = get_ip_host_name(dwLocalAddr)
        host_port = get_port_name(dwLocalPort)
        host = "{}:{}".format(host_ip, host_port)
        
        proc_name = get_name_by_pid(dwOwningPid)
        
        print("  {} {} {} {} {}({})".format(
            pad("UDP", 6),
            pad(host, 48),
            pad("*:*", 48),
            pad("", 13),
            proc_name,
            dwOwningPid
        ))
        
    win_free(table_ptr)
    win_free(size_ptr)

def show_udp6_table():
    # UDP_TABLE_OWNER_PID = 1
    # AF_INET6 = 23
    size_ptr = win_alloc(4)
    win_call("msvcrt.dll", "memset", size_ptr, 0, 4)
    
    win_call("iphlpapi.dll", "GetExtendedUdpTable", 0, size_ptr, 1, 23, 1, 0)
    
    size_bytes = win_read_mem(size_ptr, 4)
    size = size_bytes[0] | (size_bytes[1] << 8) | (size_bytes[2] << 16) | (size_bytes[3] << 24)
    
    if size == 0:
        win_free(size_ptr)
        return
        
    table_ptr = win_alloc(size)
    res = win_call("iphlpapi.dll", "GetExtendedUdpTable", table_ptr, size_ptr, 1, 23, 1, 0)
    if res["r1"] != 0:
        err_code = res.get("err_code", 0)
        err_msg = res.get("error", "")
        print("GetExtendedUdpTable (UDP6) failed with status %d (Error %d: %s)" % (res["r1"], err_code, err_msg))
        win_free(table_ptr)
        win_free(size_ptr)
        return
        
    entries_bytes = win_read_mem(table_ptr, 4)
    entries = entries_bytes[0] | (entries_bytes[1] << 8) | (entries_bytes[2] << 16) | (entries_bytes[3] << 24)
    
    # MIB_UDP6ROW_OWNER_PID is 28 bytes
    for i in range(entries):
        row_offset = 4 + i * 28
        row_bytes = win_read_mem(table_ptr + row_offset, 28)
        
        ucLocalAddr = row_bytes[0:16]
        dwLocalPort = row_bytes[20] | (row_bytes[21] << 8) | (row_bytes[22] << 16) | (row_bytes[23] << 24)
        dwOwningPid = row_bytes[24] | (row_bytes[25] << 8) | (row_bytes[26] << 16) | (row_bytes[27] << 24)
        
        host_ip = get_ip6_host_name(ucLocalAddr)
        host_port = get_port_name(dwLocalPort)
        host = "[{}]:{}".format(host_ip, host_port)
        
        proc_name = get_name_by_pid(dwOwningPid)
        
        print("  {} {} {} {} {}({})".format(
            pad("UDP6", 6),
            pad(host, 48),
            pad("*:*", 48),
            pad("", 13),
            proc_name,
            dwOwningPid
        ))
        
    win_free(table_ptr)
    win_free(size_ptr)

def netstat():
    print("Active Connections\n")
    print("  {} {} {} {} {}".format(
        pad("Proto", 6),
        pad("Local Address", 48),
        pad("Foreign Address", 48),
        pad("State", 13),
        "Process (PID)"
    ))
    print("  {} {} {} {} {}".format(
        pad("-----", 6),
        pad("-------------", 48),
        pad("---------------", 48),
        pad("-----", 13),
        "-------------"
    ))
    show_tcp_table()
    show_tcp6_table()
    show_udp_table()
    show_udp6_table()

netstat()
