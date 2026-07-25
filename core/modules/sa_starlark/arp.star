def pad(s, width):
    if len(s) < width:
        return s + " " * (width - len(s))
    return s

def int_to_arp_type(arp_type):
    if arp_type == 1:
        return "other"
    elif arp_type == 2:
        return "invalid"
    elif arp_type == 3:
        return "dynamic"
    elif arp_type == 4:
        return "static"
    else:
        return "unknown"

def print_ip_from_int(addr):
    p1 = addr & 0xFF
    p2 = (addr & 0xFF00) >> 8
    p3 = (addr & 0xFF0000) >> 16
    p4 = (addr & 0xFF000000) >> 24
    return "{}.{}.{}.{}".format(p1, p2, p3, p4)

def print_MAC_from_bytes(length, physaddr):
    if length != 6:
        return "INVALID MAC LENGTH"
    
    parts = []
    for i in range(6):
        byte = physaddr[i]
        # format as hex with leading zero
        hex_chars = "0123456789ABCDEF"
        parts.append(hex_chars[(byte >> 4) & 0xF] + hex_chars[byte & 0xF])
    return "-".join(parts)

def arp():
    # Allocate 4 bytes for length
    len_ptr = win_alloc(4)
    # Initialize length to 0
    win_call("msvcrt.dll", "memset", len_ptr, 0, 4)
    
    # GetIpNetTable(NULL, &ipNetTableBufLen, TRUE);
    # ERROR_INSUFFICIENT_BUFFER is 122 (0x7A)
    win_call("Iphlpapi.dll", "GetIpNetTable", 0, len_ptr, 1)
    
    buf_len_bytes = win_read_mem(len_ptr, 4)
    length = buf_len_bytes[0] + (buf_len_bytes[1] << 8) + (buf_len_bytes[2] << 16) + (buf_len_bytes[3] << 24)
    
    if length == 0:
        print("Could not get ipnet table info")
        win_free(len_ptr)
        return
        
    table_ptr = win_alloc(length)
    
    res = win_call("Iphlpapi.dll", "GetIpNetTable", table_ptr, len_ptr, 1)
    ret = res["r1"]
    
    if ret != 0 and ret != 234: # ERROR_MORE_DATA
        err_code = res.get("err_code", 0)
        err_msg = res.get("error", "")
        print("Error code: %d, sys error: %d (%s)" % (ret, err_code, err_msg))
        print("Could not get ipnet table info")
        win_free(table_ptr)
        win_free(len_ptr)
        return
        
    entries_bytes = win_read_mem(table_ptr, 4)
    entries = entries_bytes[0] + (entries_bytes[1] << 8) + (entries_bytes[2] << 16) + (entries_bytes[3] << 24)
    
    last_if_index = -1
    
    for p in range(entries):
        row_offset = 4 + p * 24
        row_bytes = win_read_mem(table_ptr + row_offset, 24)
        
        dwIndex = row_bytes[0] + (row_bytes[1] << 8) + (row_bytes[2] << 16) + (row_bytes[3] << 24)
        dwPhysAddrLen = row_bytes[4] + (row_bytes[5] << 8) + (row_bytes[6] << 16) + (row_bytes[7] << 24)
        bPhysAddr = row_bytes[8:16]
        dwAddr = row_bytes[16] + (row_bytes[17] << 8) + (row_bytes[18] << 16) + (row_bytes[19] << 24)
        dwType = row_bytes[20] + (row_bytes[21] << 8) + (row_bytes[22] << 16) + (row_bytes[23] << 24)
        
        if last_if_index != dwIndex:
            last_if_index = dwIndex
            print("\nInterface  --- 0x%X" % dwIndex)
            print(pad("Internet Address", 24) + pad("Physical Address", 24) + pad("Type", 24))
            
        ip_str = print_ip_from_int(dwAddr)
        
        if dwPhysAddrLen > 0:
            mac_str = print_MAC_from_bytes(dwPhysAddrLen, bPhysAddr)
        else:
            mac_str = ""
            
        type_str = int_to_arp_type(dwType)
        
        print(pad(ip_str, 24) + pad(mac_str, 24) + pad(type_str, 24))
        
    win_free(table_ptr)
    win_free(len_ptr)

arp()
