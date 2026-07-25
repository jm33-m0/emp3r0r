# Starlark implementation of aadjoininfo/entry.c

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

def get_aad_join_info():
    buf_ptr = win_alloc(8)
    res = win_call("netapi32.dll", "NetGetAadJoinInformation", 0, buf_ptr)

    if res["r1"] != 0:
        win_free(buf_ptr)
        print("[-] Host is not cloud/AAD joined (status %d)" % res["r1"])
        return "Fail"

    p = read_ptr(buf_ptr, 0)
    win_free(buf_ptr)

    if p == 0:
        print("[-] Null join info buffer returned")
        return "Fail"

    join_type = read_uint32(p, 0)
    dev_id = read_wstring(read_ptr(p, 8))
    idp_domain = read_wstring(read_ptr(p, 16))
    tenant_id = read_wstring(read_ptr(p, 24))
    tenant_name = read_wstring(read_ptr(p, 32))
    user_email = read_wstring(read_ptr(p, 40))

    type_str = "Device join" if join_type == 0 else ("Workplace join" if join_type == 1 else "Unknown")

    print("\n================== AAD/Entra ID Join Info ==================")
    print("Join Type:           " + type_str)
    print("Device ID:           " + dev_id)
    print("IDP Domain:          " + idp_domain)
    print("Tenant ID:           " + tenant_id)
    print("Tenant Display Name: " + tenant_name)
    print("Join User Email:     " + user_email)

    win_call("netapi32.dll", "NetFreeAadJoinInformation", p)
    return "OK"

def main(*args):
    return get_aad_join_info()

main()
