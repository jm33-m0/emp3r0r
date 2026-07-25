# Starlark implementation of nslookup/entry.c

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

def read_wstring(ptr):
    if ptr == 0:
        return ""
    result = ""
    for i in range(512):
        data = win_read_mem(ptr + i * 2, 2)
        c = data[0] | (data[1] << 8)
        if c == 0:
            break
        result += chr(c)
    return result

def format_ip(ip_uint32):
    b1 = ip_uint32 & 0xFF
    b2 = (ip_uint32 >> 8) & 0xFF
    b3 = (ip_uint32 >> 16) & 0xFF
    b4 = (ip_uint32 >> 24) & 0xFF
    return "%d.%d.%d.%d" % (b1, b2, b3, b4)

def utf16_ptr(s):
    if not s:
        return 0
    p = win_alloc((len(s) + 1) * 2)
    for i in range(len(s)):
        c = ord(s[i : i + 1])
        write_byte(p, i * 2, c & 0xFF)
        write_byte(p, i * 2 + 1, (c >> 8) & 0xFF)
    write_byte(p, len(s) * 2, 0)
    write_byte(p, len(s) * 2 + 1, 0)
    return p

def nslookup(hostname):
    if not hostname:
        print("[-] Usage: nslookup <hostname>")
        return "Fail"

    name_ptr = utf16_ptr(hostname)
    results_ptr = win_alloc(8)

    DNS_TYPE_A = 0x0001
    DNS_QUERY_STANDARD = 0x00000000

    res = win_call("dnsapi.dll", "DnsQuery_W", name_ptr, DNS_TYPE_A, DNS_QUERY_STANDARD, 0, results_ptr, 0)
    win_free(name_ptr)

    if res["r1"] != 0:
        err_code = res.get("err_code", 0)
        err_msg = res.get("error", "")
        win_free(results_ptr)
        print("[-] DnsQuery_W failed for %s: status %d (Error %d: %s)" % (hostname, res["r1"], err_code, err_msg))
        return "Fail"

    record_ptr = read_ptr(results_ptr, 0)
    win_free(results_ptr)

    print("DNS Lookup results for %s:" % hostname)
    print("----------------------------------------")

    curr = record_ptr
    for _ in range(32):
        if curr == 0:
            break
        next_ptr = read_ptr(curr, 0)
        rec_name = read_wstring(read_ptr(curr, 8))
        rec_type = read_uint32(curr, 16) & 0xFFFF

        if rec_type == DNS_TYPE_A:
            ip_val = read_uint32(curr, 32)
            print("Name: %s" % rec_name)
            print("IP:   %s" % format_ip(ip_val))
            print("----------------------------------------")

        curr = next_ptr

    if record_ptr != 0:
        DnsFreeRecordListDeep = 1
        win_call("dnsapi.dll", "DnsRecordListFree", record_ptr, DnsFreeRecordListDeep)

    return "OK"

def main(*args):
    hostname = args[0] if len(args) > 0 else ""
    return nslookup(hostname)

main()
