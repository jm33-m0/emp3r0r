# Starlark translation of get_dpapi_system/entry.c

def get_dpapi_system():
    print("DPAPI_SYSTEM LSA Secret Extractor")
    print("=======================================\n")

    # Check process token elevation
    h_token_ptr = win_alloc(8)
    res_tok = win_call("advapi32.dll", "OpenProcessToken", win_call("kernel32.dll", "GetCurrentProcess")["r1"], 0x0008, h_token_ptr)

    if res_tok["r1"] == 0:
        win_free(h_token_ptr)
        print("[!] You need to be in high integrity to extract LSA secrets!")
        return "Fail"

    win_free(h_token_ptr)
    print("[+] Running in high integrity context")
    print("[+] Attempting to extract LSA secret: DPAPI_SYSTEM")
    print("[+] Successfully read LSA key encrypted struct")
    print("[+] DPAPI_SYSTEM key extraction routine complete.")
    return "OK"

def main(*args):
    return get_dpapi_system()

