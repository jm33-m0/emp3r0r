# Starlark implementation of routeprint/entry.c

def pad(text, width):
    text = str(text)
    if len(text) >= width:
        return text
    return text + " " * (width - len(text))

def read_uint32(addr, offset):
    d = win_read_mem(addr + offset, 4)
    return d[0] | (d[1] << 8) | (d[2] << 16) | (d[3] << 24)

def format_ip(ip_uint32):
    b1 = ip_uint32 & 0xFF
    b2 = (ip_uint32 >> 8) & 0xFF
    b3 = (ip_uint32 >> 16) & 0xFF
    b4 = (ip_uint32 >> 24) & 0xFF
    return "%d.%d.%d.%d" % (b1, b2, b3, b4)

def routeprint():
    # MIB_IPFORWARDTABLE structure
    size_ptr = win_alloc(4)
    res = win_call("iphlpapi.dll", "GetIpForwardTable", 0, size_ptr, 1)
    size = read_uint32(size_ptr, 0)

    if size == 0:
        win_free(size_ptr)
        print("[-] GetIpForwardTable failed to get buffer size")
        return "Fail"

    table_buf = win_alloc(size)
    res2 = win_call("iphlpapi.dll", "GetIpForwardTable", table_buf, size_ptr, 1)
    win_free(size_ptr)

    if res2["r1"] != 0:
        err_code = res2.get("err_code", 0)
        err_msg = res2.get("error", "")
        win_free(table_buf)
        print("[-] GetIpForwardTable failed with status %d (Error %d: %s)" % (res2["r1"], err_code, err_msg))
        return "Fail"

    num_entries = read_uint32(table_buf, 0)

    print("===========================================================================")
    print("Active Routes:")
    print("%s %s %s %s %s" % (pad("Network Destination", 20), pad("Netmask", 18), pad("Gateway", 18), pad("Interface", 10), "Metric"))
    print("===========================================================================")

    # MIB_IPFORWARDROW struct size: 56 bytes (x64 / x86)
    # dwForwardDest(0), dwForwardMask(4), dwForwardPolicy(8), dwForwardNextHop(12),
    # dwForwardIfIndex(16), dwForwardType(20), dwForwardProto(24), dwForwardAge(28),
    # dwForwardNextHopAS(32), dwForwardMetric1(36)
    for i in range(num_entries):
        row_addr = table_buf + 4 + i * 56
        dest = format_ip(read_uint32(row_addr, 0))
        mask = format_ip(read_uint32(row_addr, 4))
        nexthop = format_ip(read_uint32(row_addr, 12))
        if_idx = read_uint32(row_addr, 16)
        metric = read_uint32(row_addr, 36)

        print("%s %s %s %s %s" % (pad(dest, 20), pad(mask, 18), pad(nexthop, 18), pad(str(if_idx), 10), str(metric)))

    print("===========================================================================")
    win_free(table_buf)
    return "OK"

def main(*args):
    return routeprint()

