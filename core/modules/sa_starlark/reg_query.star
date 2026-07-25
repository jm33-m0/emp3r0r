# Starlark implementation of reg_query/entry.c

def write_byte(addr, offset, val):
    win_call("msvcrt.dll", "memset", addr + offset, val & 0xFF, 1)

def write_uint32(addr, offset, val):
    write_byte(addr, offset, val & 0xFF)
    write_byte(addr, offset + 1, (val >> 8) & 0xFF)
    write_byte(addr, offset + 2, (val >> 16) & 0xFF)
    write_byte(addr, offset + 3, (val >> 24) & 0xFF)

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

def read_wstring(ptr, max_len=256):
    if ptr == 0:
        return ""
    result = ""
    for i in range(max_len):
        data = win_read_mem(ptr + i * 2, 2)
        c = data[0] | (data[1] << 8)
        if c == 0:
            break
        result += chr(c)
    return result

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

def parse_hive(hive_str):
    hives = {
        "HKCR": 0x80000000,
        "HKEY_CLASSES_ROOT": 0x80000000,
        "HKCU": 0x80000001,
        "HKEY_CURRENT_USER": 0x80000001,
        "HKLM": 0x80000002,
        "HKEY_LOCAL_MACHINE": 0x80000002,
        "HKU": 0x80000003,
        "HKEY_USERS": 0x80000003,
    }
    return hives.get(hive_str.upper(), 0x80000002)

def reg_query(hive_str="HKLM", subkey="", value_name=None):
    hive_val = parse_hive(hive_str)
    subkey_ptr = utf16_ptr(subkey)
    val_ptr = utf16_ptr(value_name) if value_name else 0

    h_key_ptr = win_alloc(8)
    KEY_READ = 0x20019

    res = win_call("advapi32.dll", "RegOpenKeyExW", hive_val, subkey_ptr, 0, KEY_READ, h_key_ptr)
    win_free(subkey_ptr)

    if res["r1"] != 0:
        err_code = res.get("err_code", 0)
        err_msg = res.get("error", "")
        win_free(h_key_ptr)
        if val_ptr: win_free(val_ptr)
        print("[-] RegOpenKeyExW failed: status %d (Error %d: %s)" % (res["r1"], err_code, err_msg))
        return "Fail"

    h_key = read_ptr(h_key_ptr, 0)
    win_free(h_key_ptr)

    if value_name != None:
        type_ptr = win_alloc(4)
        size_ptr = win_alloc(4)
        write_uint32(size_ptr, 0, 0)

        win_call("advapi32.dll", "RegQueryValueExW", h_key, val_ptr, 0, type_ptr, 0, size_ptr)
        size = read_uint32(size_ptr, 0)

        if size > 0:
            data_buf = win_alloc(size)
            res_val = win_call("advapi32.dll", "RegQueryValueExW", h_key, val_ptr, 0, type_ptr, data_buf, size_ptr)
            val_type = read_uint32(type_ptr, 0)

            if res_val["r1"] == 0:
                if val_type in (1, 2):  # REG_SZ, REG_EXPAND_SZ
                    str_val = read_wstring(data_buf)
                    print("%s\\%s" % (hive_str, subkey))
                    print("    %s    REG_SZ    %s" % (value_name, str_val))
                elif val_type == 4:  # REG_DWORD
                    dword_val = read_uint32(data_buf, 0)
                    print("%s\\%s" % (hive_str, subkey))
                    print("    %s    REG_DWORD    0x%x (%d)" % (value_name, dword_val, dword_val))
            win_free(data_buf)

        win_free(type_ptr)
        win_free(size_ptr)
        if val_ptr: win_free(val_ptr)
    else:
        # Enumerate values
        val_name_buf = win_alloc(512)
        val_name_len_ptr = win_alloc(4)
        type_ptr = win_alloc(4)
        data_buf = win_alloc(1024)
        data_len_ptr = win_alloc(4)

        print("%s\\%s" % (hive_str, subkey))
        print("----------------------------------------------------------------")

        for idx in range(256):
            write_uint32(val_name_len_ptr, 0, 255)
            write_uint32(data_len_ptr, 0, 1024)

            res_enum = win_call(
                "advapi32.dll",
                "RegEnumValueW",
                h_key,
                idx,
                val_name_buf,
                val_name_len_ptr,
                0,
                type_ptr,
                data_buf,
                data_len_ptr,
            )
            if res_enum["r1"] != 0:
                break

            v_name = read_wstring(val_name_buf)
            v_type = read_uint32(type_ptr, 0)
            v_size = read_uint32(data_len_ptr, 0)

            if v_type in (1, 2):
                v_str = read_wstring(data_buf)
                print("    %s    REG_SZ    %s" % (v_name if v_name else "(Default)", v_str))
            elif v_type == 4:
                v_dw = read_uint32(data_buf, 0)
                print("    %s    REG_DWORD    0x%x (%d)" % (v_name if v_name else "(Default)", v_dw, v_dw))

        win_free(val_name_buf)
        win_free(val_name_len_ptr)
        win_free(type_ptr)
        win_free(data_buf)
        win_free(data_len_ptr)

    win_call("advapi32.dll", "RegCloseKey", h_key)
    return "OK"

def main(*args):
    hive = args[0] if len(args) > 0 else "HKLM"
    key = args[1] if len(args) > 1 else ""
    value = args[2] if len(args) > 2 and args[2] and str(args[2]).lower() not in ("false", "none") else None
    return reg_query(hive, key, value)

main()
