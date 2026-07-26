# Starlark implementation of windowlist/entry.c

def pad(text, width):
    text = str(text)
    if len(text) >= width:
        return text
    return text + " " * (width - len(text))

def read_ansi_string(ptr, max_len=256):
    if ptr == 0:
        return ""
    result = ""
    for i in range(max_len):
        d = win_read_mem(ptr + i, 1)
        if d[0] == 0:
            break
        result += chr(d[0])
    return result

def windowlist(all_windows=True):
    # GW_HWNDNEXT = 2
    hwnd = win_call("user32.dll", "GetTopWindow", 0)["r1"]
    if hwnd == 0:
        print("[-] Could not retrieve top window handle")
        return "Fail"

    title_buf = win_alloc(512)

    print("%s : %s" % (pad("Window Title", 45), "Visibility"))
    print("============================================= ===========")

    for _ in range(1024):  # Safety iteration limit
        if hwnd == 0:
            break

        length_res = win_call("user32.dll", "GetWindowTextA", hwnd, title_buf, 255)
        length = length_res["r1"]

        if length > 0:
            title = read_ansi_string(title_buf, length)
            vis_res = win_call("user32.dll", "IsWindowVisible", hwnd)
            is_visible = vis_res["r1"] != 0

            if all_windows or is_visible:
                state = "Visible" if is_visible else "Hidden"
                print("%s : %s" % (pad(title, 45), state))

        hwnd = win_call("user32.dll", "GetWindow", hwnd, 2)["r1"]

    win_free(title_buf)
    return "OK"

def main(*args):
    all_raw = args[0] if len(args) > 0 else True
    all_windows = all_raw == True or all_raw == 1 or str(all_raw).lower() in ("true", "1")
    return windowlist(all_windows)

