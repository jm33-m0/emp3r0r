# Starlark implementation of dir/entry.c

def pad(text, width):
    text = str(text)
    if len(text) >= width:
        return text
    return text + " " * (width - len(text))

def write_byte(addr, offset, val):
    win_call("msvcrt.dll", "memset", addr + offset, val & 0xFF, 1)

def read_uint32(addr, offset):
    d = win_read_mem(addr + offset, 4)
    return d[0] | (d[1] << 8) | (d[2] << 16) | (d[3] << 24)

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

def list_dir(search_path="C:\\*"):
    path_ptr = utf16_ptr(search_path)
    
    # WIN32_FIND_DATAW size (x64) is 592 bytes
    find_data = win_alloc(592)

    res = win_call("kernel32.dll", "FindFirstFileW", path_ptr, find_data)
    win_free(path_ptr)

    h_find = res["r1"]
    if h_find == 0 or h_find == 0xFFFFFFFFFFFFFFFF:
        win_free(find_data)
        print("[-] FindFirstFileW failed for %s" % search_path)
        return "Fail"

    print("Directory listing for %s:" % search_path)
    print("===========================================================================")
    print("%s %s %s" % (pad("Type", 8), pad("Size (bytes)", 16), "Name"))
    print("-------- ---------------- -------------------------------------------------")

    for _ in range(4096):
        attrs = read_uint32(find_data, 0)
        size_high = read_uint32(find_data, 28)
        size_low = read_uint32(find_data, 32)
        file_size = (size_high << 32) | size_low
        file_name = read_wstring(find_data + 44)

        is_dir = (attrs & 0x10) != 0
        type_str = "<DIR>" if is_dir else "<FILE>"
        size_str = "" if is_dir else str(file_size)

        print("%s %s %s" % (pad(type_str, 8), pad(size_str, 16), file_name))

        res_next = win_call("kernel32.dll", "FindNextFileW", h_find, find_data)
        if res_next["r1"] == 0:
            break

    win_free(find_data)
    win_call("kernel32.dll", "FindClose", h_find)
    return "OK"

def main(*args):
    path = args[0] if len(args) > 0 else "C:\\*"
    return list_dir(path)

main()
