# Starlark translation of enum_filter_driver/entry.c

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

def enum_filter_drivers():
    FilterFullInformation = 0
    buf_size = 1024
    buf = win_alloc(buf_size)
    bytes_returned = win_alloc(4)
    h_filter_ptr = win_alloc(8)

    res = win_call("fltlib.dll", "FilterFindFirst", FilterFullInformation, buf, buf_size, bytes_returned, h_filter_ptr)
    if res["r1"] != 0:
        win_free(buf)
        win_free(bytes_returned)
        win_free(h_filter_ptr)
        print("[-] FilterFindFirst failed (status %d)" % res["r1"])
        return "Fail"

    h_filter = read_ptr(h_filter_ptr, 0)
    win_free(h_filter_ptr)

    print("Minifilter Drivers:")
    print("===========================================================================")

    for _ in range(128):
        name_len = win_read_mem(buf + 12, 2)
        length = (name_len[0] | (name_len[1] << 8)) // 2
        name = read_wstring(buf + 14, length)

        print("Filter Driver: %s" % name)

        res_next = win_call("fltlib.dll", "FilterFindNext", h_filter, FilterFullInformation, buf, buf_size, bytes_returned)
        if res_next["r1"] != 0:
            break

    win_free(buf)
    win_free(bytes_returned)
    win_call("fltlib.dll", "FilterFindClose", h_filter)
    return "OK"

def main(*args):
    return enum_filter_drivers()

main()
