# Starlark implementation of nettime/entry.c

def write_byte(addr, offset, val):
    win_call("msvcrt.dll", "memset", addr + offset, val & 0xFF, 1)

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

def read_uint32(addr, offset):
    d = win_read_mem(addr + offset, 4)
    return d[0] | (d[1] << 8) | (d[2] << 16) | (d[3] << 24)

def read_int32(addr, offset):
    val = read_uint32(addr, offset)
    if val >= 0x80000000:
        val -= 0x100000000
    return val

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
        return "Fail"

    tod_ptr = read_ptr(buf_ptr, 0)
    win_free(buf_ptr)

    if tod_ptr == 0:
        print("Unable to retrieve remote time: tod_ptr is NULL")
        return "Fail"

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

    date_str = "%02d/%02d/%04d %02d:%02d:%02d %s" % (month, day, year, hour12, mins, secs, ampm)
    print("Local time (GMT%+03d:00) at %s is %s" % (tz_offset_hours, srv_name, date_str))
    return "OK"

def main(*args):
    server = args[0] if len(args) > 0 and args[0] and str(args[0]).lower() not in ("false", "none") else None
    return nettime(server)

main()
