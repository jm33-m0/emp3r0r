# Starlark implementation of driversigs/entry.c and enum_filter_driver/entry.c


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
        print("[-] FilterFindFirst failed (status %d, error %d: %s)" % (res["r1"], res.get("err_code", 0), res.get("error", "")))
        return "Fail"

    h_filter = read_ptr(h_filter_ptr, 0)
    win_free(h_filter_ptr)

    print("Minifilter Drivers:")
    print("===========================================================================")

    for _ in range(128):
        # FILTER_FULL_INFORMATION struct: NextEntryOffset(0,4), FrameID(4,4), NumberOfInstances(8,4), FilterNameLength(12,2), FilterName(14,...)
        name_len = win_read_mem(buf + 12, 2)
        length = (name_len[0] | (name_len[1] << 8)) // 2
        name = read_wstring(buf + 14, length)

        print("-- %s" % name)

        res_next = win_call("fltlib.dll", "FilterFindNext", h_filter, FilterFullInformation, buf, buf_size, bytes_returned)
        if res_next["r1"] != 0:
            break

    win_free(buf)
    win_free(bytes_returned)
    win_call("fltlib.dll", "FilterFindClose", h_filter)
    return "OK"

def main(*args):
    return enum_filter_drivers()

