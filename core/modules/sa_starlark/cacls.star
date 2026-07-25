# Starlark implementation of cacls/entry.c


def get_cacls(path):
    if not path:
        print("[-] Usage: cacls <filepath>")
        return "Fail"

    path_ptr = utf16_ptr(path)
    owner_sid_ptr = win_alloc(8)
    dacl_ptr = win_alloc(8)
    sd_ptr = win_alloc(8)

    SE_FILE_OBJECT = 1
    OWNER_SECURITY_INFORMATION = 1
    DACL_SECURITY_INFORMATION = 4

    res = win_call(
        "advapi32.dll",
        "GetNamedSecurityInfoW",
        path_ptr,
        SE_FILE_OBJECT,
        OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
        owner_sid_ptr,
        0,
        dacl_ptr,
        0,
        sd_ptr,
    )
    win_free(path_ptr)

    if res["r1"] != 0:
        err_code = res.get("err_code", 0)
        err_msg = res.get("error", "")
        win_free(owner_sid_ptr)
        win_free(dacl_ptr)
        win_free(sd_ptr)
        print("[-] GetNamedSecurityInfoW failed for %s: status %d (Error %d: %s)" % (path, res["r1"], err_code, err_msg))
        return "Fail"

    p_owner_sid = read_ptr(owner_sid_ptr, 0)
    p_sd = read_ptr(sd_ptr, 0)

    win_free(owner_sid_ptr)
    win_free(dacl_ptr)
    win_free(sd_ptr)

    str_sid_ptr = win_alloc(8)
    win_call("advapi32.dll", "ConvertSidToStringSidW", p_owner_sid, str_sid_ptr)
    p_str = read_ptr(str_sid_ptr, 0)
    win_free(str_sid_ptr)

    sid_str = read_wstring(p_str)
    if p_str != 0:
        win_call("kernel32.dll", "LocalFree", p_str)

    print("Permissions for %s:" % path)
    print("----------------------------------------")
    print("Owner SID: %s" % sid_str)

    if p_sd != 0:
        win_call("kernel32.dll", "LocalFree", p_sd)

    return "OK"

def main(*args):
    path = args[0] if len(args) > 0 else ""
    return get_cacls(path)

main()
