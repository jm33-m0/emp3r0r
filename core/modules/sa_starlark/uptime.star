# Starlark implementation of uptime/entry.c



def main(*args):
    # Counts millisecond ticks since last boot
    res = win_call("kernel32.dll", "GetTickCount64")
    ticks = res["r1"]
    
    seconds = ticks // 1000
    minutes = seconds // 60
    hours = minutes // 60
    days = hours // 24
    
    print("Uptime: %d days, %d hours, %d minutes, %d seconds" % (days, hours % 24, minutes % 60, seconds % 60))
    
    cur_time_ptr = win_alloc(16)  # sizeof(SYSTEMTIME)
    cur_ftime_ptr = win_alloc(8)  # sizeof(FILETIME)
    
    # Get local time
    win_call("kernel32.dll", "GetLocalTime", cur_time_ptr)
    
    wYear = read_uint16(cur_time_ptr, 0)
    wMonth = read_uint16(cur_time_ptr, 2)
    wDay = read_uint16(cur_time_ptr, 6)
    wHour = read_uint16(cur_time_ptr, 8)
    wMinute = read_uint16(cur_time_ptr, 10)
    wSecond = read_uint16(cur_time_ptr, 12)
    
    print(sprintf("Local time: %04d-%02d-%02d %02d:%02d:%02d", wYear, wMonth, wDay, wHour, wMinute, wSecond))
    
    # Convert local SystemTime to FileTime
    win_call("kernel32.dll", "SystemTimeToFileTime", cur_time_ptr, cur_ftime_ptr)
    
    # Subtract uptime in 100-nanosecond intervals (ticks * 10000)
    utime = read_uint64(cur_ftime_ptr, 0)
    sub_val = ticks * 10000
    utime = utime - sub_val if utime >= sub_val else 0
    
    # Write boot file time back
    write_uint64(cur_ftime_ptr, utime)
    
    # Convert back to SystemTime
    res_ft = win_call("kernel32.dll", "FileTimeToSystemTime", cur_ftime_ptr, cur_time_ptr)
    
    if res_ft["r1"] != 0:
        bYear = read_uint16(cur_time_ptr, 0)
        bMonth = read_uint16(cur_time_ptr, 2)
        bDay = read_uint16(cur_time_ptr, 6)
        bHour = read_uint16(cur_time_ptr, 8)
        bMinute = read_uint16(cur_time_ptr, 10)
        bSecond = read_uint16(cur_time_ptr, 12)
        print(sprintf("Boot time: %04d-%02d-%02d %02d:%02d:%02d", bYear, bMonth, bDay, bHour, bMinute, bSecond))
    else:
        print("Boot time: Unknown")
    
    win_free(cur_time_ptr)
    win_free(cur_ftime_ptr)
    return "OK"
