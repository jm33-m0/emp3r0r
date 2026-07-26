# Starlark implementation of useridletime/entry.c

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

def userIdletime():
    # LASTINPUTINFO layout (8 bytes): cbSize (uint32) + dwTime (uint32)
    lii = win_alloc(8)
    write_uint32(lii, 0, 8)  # sizeof(LASTINPUTINFO)

    res = win_call("user32.dll", "GetLastInputInfo", lii)
    if res["r1"] != 0:
        dwTime = read_uint32(lii, 4)
        win_free(lii)

        res_tick = win_call("kernel32.dll", "GetTickCount")
        tickCount = res_tick["r1"] & 0xFFFFFFFF

        idleTime = (tickCount - dwTime) // 1000
        if idleTime < 0:
            idleTime = 0

        seconds = idleTime % 60
        minutes = (idleTime // 60) % 60
        hours = (idleTime // 3600) % 24
        days = idleTime // 86400

        print("Current User idle time: %d days, %d hours, %d minutes, %d seconds" % (days, hours, minutes, seconds))
        return "OK"
    else:
        err_code = res.get("err_code", 0)
        err_msg = res.get("error", "")
        win_free(lii)
        print("Failed to retrieve last user idle time. Error %d: %s" % (err_code, err_msg))
        return "Fail"

def main(*args):
    return userIdletime()

