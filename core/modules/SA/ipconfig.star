# Starlark implementation of ipconfig/entry.c


def format_mac(addr_mem, length):
    parts = []
    for i in range(length):
        b = addr_mem[i]
        h = "0123456789ABCDEF"
        parts.append(h[(b >> 4) & 0xF] + h[b & 0xF])
    return "-".join(parts)

def ipconfig():
    # 1. GetNetworkParams for global hostname and domain
    size_ptr = win_alloc(4)
    win_call("iphlpapi.dll", "GetNetworkParams", 0, size_ptr)
    size = read_uint32(size_ptr, 0)
    
    if size > 0:
        fixed_info = win_alloc(size)
        res = win_call("iphlpapi.dll", "GetNetworkParams", fixed_info, size_ptr)
        if res["r1"] == 0:
            hostname = read_ansi_string(fixed_info, 132)  # HostName (offset 0)
            domain = read_ansi_string(fixed_info + 132, 132)  # DomainName (offset 132)
            print("\nWindows IP Configuration\n")
            print("   Host Name . . . . . . . . . . . . : " + hostname)
            print("   Primary Dns Suffix  . . . . . . . : " + domain)
        win_free(fixed_info)
    win_free(size_ptr)

    # 2. GetAdaptersInfo for adapter details
    # IP_ADAPTER_INFO struct size (x64): 648 bytes
    size_ptr2 = win_alloc(4)
    win_call("iphlpapi.dll", "GetAdaptersInfo", 0, size_ptr2)
    size2 = read_uint32(size_ptr2, 0)

    if size2 > 0:
        info_buf = win_alloc(size2)
        res2 = win_call("iphlpapi.dll", "GetAdaptersInfo", info_buf, size_ptr2)
        if res2["r1"] == 0:
            curr = info_buf
            for _ in range(32): # safety limit
                if curr == 0:
                    break
                next_ptr = read_ptr(curr, 0)
                desc = read_ansi_string(curr + 268, 128)  # Description at offset 268
                mac_len = read_uint32(curr + 400, 0)      # AddressLength at offset 400
                mac_raw = win_read_mem(curr + 404, mac_len if mac_len <= 8 else 8) if mac_len > 0 else []
                mac_str = format_mac(mac_raw, len(mac_raw)) if len(mac_raw) > 0 else ""

                ip_str = read_ansi_string(curr + 432, 16)      # IpAddressList.IpAddress at 432
                mask_str = read_ansi_string(curr + 448, 16)    # IpAddressList.IpMask at 448
                gateway_str = read_ansi_string(curr + 472, 16) # GatewayList.IpAddress at 472
                dhcp_enabled = read_uint32(curr + 512, 0)       # DhcpEnabled at 512
                dhcp_server = read_ansi_string(curr + 524, 16)  # DhcpServer.IpAddress at 524

                print("\nEthernet adapter %s:\n" % desc)
                print("   Description . . . . . . . . . . . : " + desc)
                print("   Physical Address. . . . . . . . . : " + mac_str)
                print("   DHCP Enabled. . . . . . . . . . . : %s" % ("Yes" if dhcp_enabled else "No"))
                print("   IPv4 Address. . . . . . . . . . . : " + ip_str)
                print("   Subnet Mask . . . . . . . . . . . : " + mask_str)
                print("   Default Gateway . . . . . . . . . : " + gateway_str)
                if dhcp_enabled and dhcp_server:
                    print("   DHCP Server . . . . . . . . . . . : " + dhcp_server)

                curr = next_ptr
        win_free(info_buf)
    win_free(size_ptr2)
    return "OK"

def main(*args):
    return ipconfig()

