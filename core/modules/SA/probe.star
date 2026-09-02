# Starlark implementation of probe/entry.c

def write_byte(addr, offset, val):
    win_call("msvcrt.dll", "memset", addr + offset, val & 0xFF, 1)

def write_uint16(addr, offset, val):
    write_byte(addr, offset, (val >> 8) & 0xFF)
    write_byte(addr, offset + 1, val & 0xFF)

def write_uint32(addr, offset, val):
    write_byte(addr, offset, val & 0xFF)
    write_byte(addr, offset + 1, (val >> 8) & 0xFF)
    write_byte(addr, offset + 2, (val >> 16) & 0xFF)
    write_byte(addr, offset + 3, (val >> 24) & 0xFF)

def probe(host, port):
    if not host or not port:
        print("[-] Usage: probe <host> <port>")
        return "Fail"

    port_num = int(port)
    ws_data = win_alloc(400)
    win_call("ws2_32.dll", "WSAStartup", 0x0202, ws_data)
    win_free(ws_data)

    AF_INET = 2
    SOCK_STREAM = 1
    IPPROTO_TCP = 6

    res_sock = win_call("ws2_32.dll", "socket", AF_INET, SOCK_STREAM, IPPROTO_TCP)
    sock = res_sock["r1"]
    if sock == 0 or sock == 0xFFFFFFFFFFFFFFFF:
        print("[-] socket creation failed (error %d: %s)" % (res_sock.get("err_code", 0), res_sock.get("error", "")))
        return "Fail"

    # sockaddr_in: sin_family (2 bytes), sin_port (2 bytes), sin_addr (4 bytes), sin_zero (8 bytes)
    sockaddr = win_alloc(16)
    write_uint16(sockaddr, 0, AF_INET) # Network byte order for sin_family
    win_call("msvcrt.dll", "memset", sockaddr, AF_INET, 1)
    write_byte(sockaddr, 1, 0)
    write_uint16(sockaddr, 2, port_num) # sin_port in big-endian

    host_ptr = win_alloc(len(host) + 1)
    for i in range(len(host)):
        write_byte(host_ptr, i, ord(host[i]))
    write_byte(host_ptr, len(host), 0)

    ip_val = win_call("ws2_32.dll", "inet_addr", host_ptr)["r1"]
    win_free(host_ptr)

    write_uint32(sockaddr, 4, ip_val)

    res = win_call("ws2_32.dll", "connect", sock, sockaddr, 16)
    win_free(sockaddr)
    win_call("ws2_32.dll", "closesocket", sock)

    if res["r1"] == 0:
        print("[+] Connection to %s:%d SUCCEEDED" % (host, port_num))
        return "OK"
    else:
        print("[-] Connection to %s:%d FAILED (error %d: %s)" % (host, port_num, res.get("err_code", 0), res.get("error", "")))
        return "Fail"

def main(*args):
    host = args[0] if len(args) > 0 else ""
    port = args[1] if len(args) > 1 else "80"
    return probe(host, port)

