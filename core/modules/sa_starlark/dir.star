# Starlark implementation of dir/entry.c


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
