# Starlark implementation of locale/entry.c

def read_wstring(ptr, max_len=256):
    result = ""
    offset = 0
    for i in range(max_len):
        data = win_read_mem(ptr + offset, 2)
        b0 = data[0]
        b1 = data[1]
        char_code = b0 | (b1 << 8)
        if char_code == 0:
            break
        result += chr(char_code)
        offset += 2
    return result

def main(*args):
    BUFFER_SIZE = 85
    name_ptr = win_alloc(BUFFER_SIZE * 2)
    wc_buffer_ptr = win_alloc(BUFFER_SIZE * 2)
    sys_time_ptr = win_alloc(BUFFER_SIZE * 2)
    geoid_ptr = win_alloc(BUFFER_SIZE * 2)
    
    # GetSystemDefaultLocaleName
    res = win_call("kernel32.dll", "GetSystemDefaultLocaleName", name_ptr, BUFFER_SIZE)
    if res["r1"] == 0:
        print("Error retrieving system locale information: Error %d: %s" % (res.get("err_code", 0), res.get("error", "")))
        win_free(name_ptr)
        win_free(wc_buffer_ptr)
        win_free(sys_time_ptr)
        win_free(geoid_ptr)
        return "Fail"
    
    name = read_wstring(name_ptr, BUFFER_SIZE)
    
    # GetLocaleInfoEx for LOCALE_SENGLANGUAGE (0x00001001)
    res = win_call("kernel32.dll", "GetLocaleInfoEx", name_ptr, 0x1001, wc_buffer_ptr, BUFFER_SIZE)
    lang = "Unknown"
    if res["r1"] == 0:
        print("Error retrieving language: Error %d: %s" % (res.get("err_code", 0), res.get("error", "")))
    else:
        lang = read_wstring(wc_buffer_ptr, BUFFER_SIZE)
    
    # LocaleNameToLCID
    res = win_call("kernel32.dll", "LocaleNameToLCID", name_ptr, 0)
    lcid = res["r1"]
    if lcid == 0:
        print("Error mapping Locale Name to a Locale ID: Error %d: %s" % (res.get("err_code", 0), res.get("error", "")))
    
    # GetDateFormatEx for DATE_LONGDATE (0x02)
    res = win_call("kernel32.dll", "GetDateFormatEx", name_ptr, 0x02, 0, 0, sys_time_ptr, BUFFER_SIZE, 0)
    date_str = "Unknown"
    if res["r1"] == 0:
        print("Error retrieving system date/time: Error %d: %s" % (res.get("err_code", 0), res.get("error", "")))
    else:
        date_str = read_wstring(sys_time_ptr, BUFFER_SIZE)
        
    # GetLocaleInfoEx for LOCALE_SLOCALIZEDCOUNTRYNAME (0x06)
    res = win_call("kernel32.dll", "GetLocaleInfoEx", name_ptr, 0x06, geoid_ptr, BUFFER_SIZE)
    country = "Unknown"
    if res["r1"] == 0:
        print("Error retrieving geolocation id: Error %d: %s" % (res.get("err_code", 0), res.get("error", "")))
    else:
        country = read_wstring(geoid_ptr, BUFFER_SIZE)
        
    print("Locale: %s (%s)" % (lang, name))
    print("LCID: %x" % lcid)
    print("Date: %s" % date_str)
    print("Country: %s" % country)
    
    win_free(name_ptr)
    win_free(wc_buffer_ptr)
    win_free(sys_time_ptr)
    win_free(geoid_ptr)
    return "OK"
