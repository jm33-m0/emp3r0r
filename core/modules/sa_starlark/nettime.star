# Starlark implementation of nettime/entry.c



def nettime(server=None):
    server_ptr = utf16_ptr(server) if server else 0
    buf_ptr = win_alloc(8)

    res = win_call("netapi32.dll", "NetRemoteTOD", server_ptr, buf_ptr)
    if server_ptr != 0:
        win_free(server_ptr)

    if res["r1"] != 0:
        err_code = res.get("err_code", 0)
        err_msg = res.get("error", "")
        win_free(buf_ptr)
        print("Unable to retrieve remote time: status %d (Error %d: %s)" % (res["r1"], err_code, err_msg))
        return "OK"

    tod_ptr = read_ptr(buf_ptr, 0)
    win_free(buf_ptr)

    if tod_ptr == 0:
        print("Unable to retrieve remote time: tod_ptr is NULL")
        return "OK"

    month = read_uint32(tod_ptr, 36)
    day = read_uint32(tod_ptr, 32)
    year = read_uint32(tod_ptr, 40)
    hours = read_uint32(tod_ptr, 8)
    mins = read_uint32(tod_ptr, 12)
    secs = read_uint32(tod_ptr, 16)
    tz_bias = read_int32(tod_ptr, 24)

    win_call("netapi32.dll", "NetApiBufferFree", tod_ptr)

    srv_name = server if server else "localhost"
    tz_offset_hours = -tz_bias // 60
    
    # Format AM/PM
    ampm = "AM"
    hour12 = hours
    if hour12 >= 12:
        ampm = "PM"
        if hour12 > 12:
            hour12 -= 12
    if hour12 == 0:
        hour12 = 12

    date_str = sprintf("%02d/%02d/%04d %02d:%02d:%02d %s", month, day, year, hour12, mins, secs, ampm)
    print(sprintf("Local time (GMT%+03d:00) at %s is %s", tz_offset_hours, srv_name, date_str))
    return "OK"

def main(*args):
    server = args[0] if len(args) > 0 and args[0] and str(args[0]).lower() not in ("false", "none") else None
    return nettime(server)

main()
