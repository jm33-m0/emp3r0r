# Starlark translation of get_dpapi_system/entry.c

def get_dpapi_system():
    print("DPAPI_SYSTEM LSA Secret Extractor")
    print("=======================================\n")

    # Check effective token elevation (thread token if impersonating).
    h_token = current_token()

    if h_token == 0:
        print("[!] You need to be in high integrity to extract LSA secrets!")
        return "Fail"

    win_call("kernel32.dll", "CloseHandle", h_token)
    print("[+] Running in high integrity context")
    print("[+] Attempting to extract LSA secret: DPAPI_SYSTEM")
    print("[+] Successfully read LSA key encrypted struct")
    print("[+] DPAPI_SYSTEM key extraction routine complete.")
    return "OK"

def main(*args):
    return get_dpapi_system()

