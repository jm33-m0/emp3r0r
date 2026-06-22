# Demo Starlark script demonstrating the scripting engine capabilities

def main(*args):
    print("==================================================")
    print("Starlark module execution started.")
    print("Arguments received in argv list: " + str(argv))
    print("Arguments passed to main: " + str(args))
    print("==================================================")

    # 1. Target file configuration
    target = "starlark_test.txt"
    if len(argv) > 0:
        target = argv[0]

    print("[*] Working with target file: " + target)

    # 2. Filesystem API testing
    print("[*] Writing content to target file...")
    write_file(target, "Starlark execution demo content.\nHello from the Starlark Go API!")

    print("[*] Verifying file exists...")
    if exists(target):
        print("[+] Success: file exists.")
        print("[*] Reading file content:")
        content = read_file(target)
        print("--- CONTENT START ---")
        print(content)
        print("---- CONTENT END ----")
    else:
        print("[-] Error: file was not written successfully.")

    # 3. Listing directory
    print("[*] Listing current directory:")
    files = list_dir(".")
    if target in files:
        print("[+] Success: target file found in directory list.")
    else:
        print("[-] Warning: target file not found in directory list.")

    # 4. Cleaning up file
    print("[*] Removing target file...")
    remove(target)
    if not exists(target):
        print("[+] Success: file cleaned up.")
    else:
        print("[-] Error: failed to remove file.")

    # 5. Executing system command
    print("[*] Executing system command...")
    whoami_out = exec_cmd("whoami")
    print("[+] Output: " + whoami_out.strip())

    print("==================================================")
    print("Starlark execution finished.")
    print("==================================================")
    return "Demo execution completed successfully!"
