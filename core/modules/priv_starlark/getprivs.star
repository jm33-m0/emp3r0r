# Starlark translation of GetPrivs() from priv_windows.go
#
# getProcessIntegrityLevel(processToken windows.Token) (string, error)
# lookupPrivilegeNameByLUID(luid uint64) (string, string, error)
# GetPrivs() ([]PrivilegeInfo, string, string, error)
#
# Every Win32 API call matches the Go original word-for-word.

# ── Constants from priv_windows.go ────────────────────────────────────────────
SECURITY_MANDATORY_LOW_RID = 0x00001000
SECURITY_MANDATORY_MEDIUM_RID = 0x00002000
SECURITY_MANDATORY_HIGH_RID = 0x00003000
SECURITY_MANDATORY_SYSTEM_RID = 0x00004000

# TOKEN_PRIVILEGES attribute flags (windows package)
SE_PRIVILEGE_ENABLED_BY_DEFAULT = 0x00000001
SE_PRIVILEGE_ENABLED = 0x00000002
SE_PRIVILEGE_REMOVED = 0x00000004
SE_PRIVILEGE_USED_FOR_ACCESS = 0x80000000

# windows.TOKEN_QUERY
TOKEN_QUERY = 0x0008


# ── Memory helpers ────────────────────────────────────────────────────────────
def read_uint32(addr, offset):
    d = win_read_mem(addr + offset, 4)
    return d[0] | (d[1] << 8) | (d[2] << 16) | (d[3] << 24)


def read_ptr(addr, offset):
    d = win_read_mem(addr + offset, 8)
    return (
        d[0]
        | (d[1] << 8)
        | (d[2] << 16)
        | (d[3] << 24)
        | (d[4] << 32)
        | (d[5] << 40)
        | (d[6] << 48)
        | (d[7] << 56)
    )


def read_wstring(ptr):
    result = ""
    off = 0
    for _ in range(512):
        d = win_read_mem(ptr + off, 2)
        c = d[0] | (d[1] << 8)
        if c == 0:
            break
        result += chr(c)
        off += 2
    return result


def write_byte(addr, offset, val):
    win_call("msvcrt.dll", "memset", addr + offset, val & 0xFF, 1)


def write_uint32(addr, offset, val):
    write_byte(addr, offset, val & 0xFF)
    write_byte(addr, offset + 1, (val >> 8) & 0xFF)
    write_byte(addr, offset + 2, (val >> 16) & 0xFF)
    write_byte(addr, offset + 3, (val >> 24) & 0xFF)


def pad(text, width):
    text = str(text)
    if len(text) >= width:
        return text
    return text + " " * (width - len(text))


# ── getProcessIntegrityLevel ───────────────────────────────────────────────────
def getProcessIntegrityLevel(processToken):
    """
    func getProcessIntegrityLevel(processToken windows.Token) (string, error) {
        var tokenIntegrityBufferSize uint32
        windows.GetTokenInformation(processToken, windows.TokenIntegrityLevel,
            nil, 0, &tokenIntegrityBufferSize)
        if tokenIntegrityBufferSize < 4 { return "Unknown", nil }
        tokenIntegrityBuffer := make([]byte, tokenIntegrityBufferSize)
        err := windows.GetTokenInformation(processToken, windows.TokenIntegrityLevel,
            &tokenIntegrityBuffer[0], tokenIntegrityBufferSize, &tokenIntegrityBufferSize)
        var privilegeLevel uint32 = binary.LittleEndian.Uint32(
            tokenIntegrityBuffer[tokenIntegrityBufferSize-4:])
        if privilegeLevel < SECURITY_MANDATORY_LOW_RID    { return "Untrusted", nil }
        else if privilegeLevel < SECURITY_MANDATORY_MEDIUM_RID { return "Low", nil }
        else if privilegeLevel >= SECURITY_MANDATORY_MEDIUM_RID && privilegeLevel < SECURITY_MANDATORY_HIGH_RID { return "Medium", nil }
        else if privilegeLevel >= SECURITY_MANDATORY_HIGH_RID  { return "High", nil }
        return "Unknown", nil
    }
    """
    TokenIntegrityLevel = 25  # windows.TokenIntegrityLevel

    # var tokenIntegrityBufferSize uint32
    sizePtr = win_alloc(4)

    # windows.GetTokenInformation(processToken, windows.TokenIntegrityLevel,
    #     nil, 0, &tokenIntegrityBufferSize)
    win_call(
        "advapi32.dll",
        "GetTokenInformation",
        processToken,
        TokenIntegrityLevel,
        0,
        0,
        sizePtr,
    )

    tokenIntegrityBufferSize = read_uint32(sizePtr, 0)
    win_free(sizePtr)

    # if tokenIntegrityBufferSize < 4 { return "Unknown", nil }
    if tokenIntegrityBufferSize < 4:
        return "Unknown"

    # tokenIntegrityBuffer := make([]byte, tokenIntegrityBufferSize)
    tokenIntegrityBuffer = win_alloc(tokenIntegrityBufferSize)

    sizePtr2 = win_alloc(4)
    # err := windows.GetTokenInformation(processToken, windows.TokenIntegrityLevel,
    #     &tokenIntegrityBuffer[0], tokenIntegrityBufferSize, &tokenIntegrityBufferSize)
    res = win_call(
        "advapi32.dll",
        "GetTokenInformation",
        processToken,
        TokenIntegrityLevel,
        tokenIntegrityBuffer,
        tokenIntegrityBufferSize,
        sizePtr2,
    )
    retSize = read_uint32(sizePtr2, 0)
    win_free(sizePtr2)

    if res["r1"] == 0:
        win_free(tokenIntegrityBuffer)
        return "Unknown"

    # var privilegeLevel uint32 = binary.LittleEndian.Uint32(tokenIntegrityBuffer[tokenIntegrityBufferSize-4:])
    # (last 4 bytes of the buffer)
    privilegeLevel = read_uint32(tokenIntegrityBuffer, retSize - 4)
    win_free(tokenIntegrityBuffer)

    # if privilegeLevel < SECURITY_MANDATORY_LOW_RID    { return "Untrusted", nil }
    if privilegeLevel < SECURITY_MANDATORY_LOW_RID:
        return "Untrusted"
    # else if privilegeLevel < SECURITY_MANDATORY_MEDIUM_RID { return "Low", nil }
    elif privilegeLevel < SECURITY_MANDATORY_MEDIUM_RID:
        return "Low"
    # else if privilegeLevel >= SECURITY_MANDATORY_MEDIUM_RID && privilegeLevel < SECURITY_MANDATORY_HIGH_RID
    elif (
        privilegeLevel >= SECURITY_MANDATORY_MEDIUM_RID
        and privilegeLevel < SECURITY_MANDATORY_HIGH_RID
    ):
        return "Medium"
    # else if privilegeLevel >= SECURITY_MANDATORY_HIGH_RID { return "High", nil }
    elif privilegeLevel >= SECURITY_MANDATORY_HIGH_RID:
        return "High"

    return "Unknown"


# ── lookupPrivilegeNameByLUID ──────────────────────────────────────────────────
def lookupPrivilegeNameByLUID(luid_addr):
    """
    func lookupPrivilegeNameByLUID(luid uint64) (string, string, error) {
        nameBuffer := make([]uint16, 256)
        nameBufferSize := uint32(len(nameBuffer))
        displayNameBuffer := make([]uint16, 256)
        displayNameBufferSize := uint32(len(displayNameBuffer))
        systemName := ""
        var langID uint32
        err := syscalls.LookupPrivilegeNameW(systemName, &luid, &nameBuffer[0], &nameBufferSize)
        err = syscalls.LookupPrivilegeDisplayNameW(systemName, &nameBuffer[0],
            &displayNameBuffer[0], &displayNameBufferSize, &langID)
        return syscall.UTF16ToString(nameBuffer), syscall.UTF16ToString(displayNameBuffer), nil
    }
    luid_addr: address of the LUID in memory (not the value itself).
    """
    # nameBuffer := make([]uint16, 256)
    nameBuffer = win_alloc(512)  # 256 * 2 bytes
    # nameBufferSize := uint32(len(nameBuffer))
    nameBufferSize = win_alloc(4)
    write_uint32(nameBufferSize, 0, 256)

    # displayNameBuffer := make([]uint16, 256)
    displayNameBuffer = win_alloc(512)
    # displayNameBufferSize := uint32(len(displayNameBuffer))
    displayNameBufferSize = win_alloc(4)
    write_uint32(displayNameBufferSize, 0, 256)

    # systemName := ""  → NULL pointer (local machine)
    systemName = 0

    # var langID uint32
    langID = win_alloc(4)

    # err := syscalls.LookupPrivilegeNameW(systemName, &luid, &nameBuffer[0], &nameBufferSize)
    res1 = win_call(
        "advapi32.dll",
        "LookupPrivilegeNameW",
        systemName,
        luid_addr,
        nameBuffer,
        nameBufferSize,
    )

    priv_name = ""
    display_name = ""

    if res1["r1"] != 0:
        priv_name = read_wstring(nameBuffer)

        # err = syscalls.LookupPrivilegeDisplayNameW(systemName, &nameBuffer[0],
        #     &displayNameBuffer[0], &displayNameBufferSize, &langID)
        res2 = win_call(
            "advapi32.dll",
            "LookupPrivilegeDisplayNameW",
            systemName,
            nameBuffer,
            displayNameBuffer,
            displayNameBufferSize,
            langID,
        )
        if res2["r1"] != 0:
            display_name = read_wstring(displayNameBuffer)

    win_free(nameBuffer)
    win_free(nameBufferSize)
    win_free(displayNameBuffer)
    win_free(displayNameBufferSize)
    win_free(langID)

    return priv_name, display_name


# ── GetPrivs ───────────────────────────────────────────────────────────────────
def GetPrivs():
    """
    func GetPrivs() ([]PrivilegeInfo, string, string, error) {
        var tokenHandle windows.Token
        var integrity string
        var processName string
        var tokenInfoBufferSize uint32
        currentProcHandle := windows.CurrentProcess()
        sessionPID, err := windows.GetProcessId(currentProcHandle)
        processInformation, err := ps.FindProcess(int(sessionPID), false)
        if processInformation != nil { processName = processInformation.Executable() }
        err = windows.OpenProcessToken(currentProcHandle, windows.TOKEN_QUERY, &tokenHandle)
        windows.GetTokenInformation(tokenHandle, windows.TokenPrivileges,
            nil, 0, &tokenInfoBufferSize)
        tokenInfoBuffer := bytes.NewBuffer(make([]byte, tokenInfoBufferSize))
        err = windows.GetTokenInformation(tokenHandle, windows.TokenPrivileges,
            &tokenInfoBuffer.Bytes()[0], uint32(tokenInfoBuffer.Len()), &tokenInfoBufferSize)
        var privilegeCount uint32
        binary.Read(tokenInfoBuffer, binary.LittleEndian, &privilegeCount)
        for index := 0; index < int(privilegeCount); index++ {
            var luid uint64
            var attributes uint32
            binary.Read(tokenInfoBuffer, binary.LittleEndian, &luid)
            binary.Read(tokenInfoBuffer, binary.LittleEndian, &attributes)
            currentPrivInfo.Name, currentPrivInfo.Description, err = lookupPrivilegeNameByLUID(luid)
            currentPrivInfo.EnabledByDefault = (attributes & windows.SE_PRIVILEGE_ENABLED_BY_DEFAULT) > 0
            currentPrivInfo.UsedForAccess    = (attributes & windows.SE_PRIVILEGE_USED_FOR_ACCESS)    > 0
            currentPrivInfo.Enabled          = (attributes & windows.SE_PRIVILEGE_ENABLED)            > 0
            currentPrivInfo.Removed          = (attributes & windows.SE_PRIVILEGE_REMOVED)            > 0
        }
        integrity, err = getProcessIntegrityLevel(tokenHandle)
        return privInfo, integrity, processName, nil
    }
    """
    TokenPrivileges = 3  # windows.TokenPrivileges

    # var tokenHandle windows.Token
    tokenHandle_ptr = win_alloc(8)

    # currentProcHandle := windows.CurrentProcess()
    currentProcHandle = win_call("kernel32.dll", "GetCurrentProcess")["r1"]

    # sessionPID, err := windows.GetProcessId(currentProcHandle)
    sessionPID = win_call("kernel32.dll", "GetProcessId", currentProcHandle)["r1"]

    # processName: use QueryFullProcessImageNameA to mimic ps.FindProcess().Executable()
    processName = ""
    if sessionPID != 0:
        PROCESS_QUERY_INFORMATION = 0x0400
        h_self = win_call(
            "kernel32.dll", "OpenProcess", PROCESS_QUERY_INFORMATION, 0, sessionPID
        )["r1"]
        if h_self != 0:
            name_buf = win_alloc(512)
            sz_ptr = win_alloc(4)
            write_uint32(sz_ptr, 0, 256)
            res = win_call(
                "kernel32.dll",
                "QueryFullProcessImageNameA",
                h_self,
                0,
                name_buf,
                sz_ptr,
            )
            if res["r1"] != 0:
                length = read_uint32(sz_ptr, 0)
                if length > 0:
                    raw = win_read_mem(name_buf, length)
                    for b in raw:
                        processName += chr(b)
            win_free(name_buf)
            win_free(sz_ptr)
            win_call("kernel32.dll", "CloseHandle", h_self)

    # err = windows.OpenProcessToken(currentProcHandle, windows.TOKEN_QUERY, &tokenHandle)
    res = win_call(
        "advapi32.dll",
        "OpenProcessToken",
        currentProcHandle,
        TOKEN_QUERY,
        tokenHandle_ptr,
    )
    if res["r1"] == 0:
        win_free(tokenHandle_ptr)
        print("[-] OpenProcessToken failed")
        return

    tokenHandle = read_ptr(tokenHandle_ptr, 0)
    win_free(tokenHandle_ptr)

    # var tokenInfoBufferSize uint32
    sizePtr = win_alloc(4)

    # windows.GetTokenInformation(tokenHandle, windows.TokenPrivileges,
    #     nil, 0, &tokenInfoBufferSize)
    win_call(
        "advapi32.dll",
        "GetTokenInformation",
        tokenHandle,
        TokenPrivileges,
        0,
        0,
        sizePtr,
    )

    tokenInfoBufferSize = read_uint32(sizePtr, 0)
    win_free(sizePtr)

    # tokenInfoBuffer := bytes.NewBuffer(make([]byte, tokenInfoBufferSize))
    tokenInfoBuffer = win_alloc(tokenInfoBufferSize)

    sizePtr2 = win_alloc(4)
    # err = windows.GetTokenInformation(tokenHandle, windows.TokenPrivileges,
    #     &tokenInfoBuffer.Bytes()[0], uint32(tokenInfoBuffer.Len()), &tokenInfoBufferSize)
    res = win_call(
        "advapi32.dll",
        "GetTokenInformation",
        tokenHandle,
        TokenPrivileges,
        tokenInfoBuffer,
        tokenInfoBufferSize,
        sizePtr2,
    )
    win_free(sizePtr2)

    if res["r1"] == 0:
        win_free(tokenInfoBuffer)
        win_call("kernel32.dll", "CloseHandle", tokenHandle)
        print("[-] GetTokenInformation (privileges) failed")
        return

    # var privilegeCount uint32
    # binary.Read(tokenInfoBuffer, binary.LittleEndian, &privilegeCount)
    privilegeCount = read_uint32(tokenInfoBuffer, 0)

    # ── Print header ─────────────────────────────────────────────────────────
    print("Process: %s  PID: %d" % (processName, sessionPID))
    print("")
    print(
        "%s%s%s%s%s"
        % (
            pad("Privilege Name", 40),
            pad("Description", 52),
            pad("State", 10),
            pad("Default", 10),
            pad("Removed", 10),
        )
    )
    print(
        "%s%s%s%s%s"
        % (
            pad("=" * 38, 40),
            pad("=" * 50, 52),
            pad("=" * 7, 10),
            pad("=" * 7, 10),
            pad("=" * 7, 10),
        )
    )

    # Iterate over LUID_AND_ATTRIBUTES array.
    # Layout per entry (after the leading PrivilegeCount DWORD):
    #   LUID (8 bytes) + Attributes (4 bytes) = 12 bytes each.
    # Buffer layout: PrivilegeCount(4 bytes) + entries start at offset 4
    readPos = 4  # skip PrivilegeCount

    for index in range(privilegeCount):
        # var luid uint64
        # binary.Read(tokenInfoBuffer, binary.LittleEndian, &luid)
        luid_addr = tokenInfoBuffer + readPos

        # var attributes uint32
        # binary.Read(tokenInfoBuffer, binary.LittleEndian, &attributes)
        attributes = read_uint32(tokenInfoBuffer, readPos + 8)

        readPos += 12  # sizeof(LUID_AND_ATTRIBUTES) = 8 + 4

        # currentPrivInfo.Name, currentPrivInfo.Description, err = lookupPrivilegeNameByLUID(luid)
        priv_name, priv_desc = lookupPrivilegeNameByLUID(luid_addr)

        # currentPrivInfo.EnabledByDefault = (attributes & windows.SE_PRIVILEGE_ENABLED_BY_DEFAULT) > 0
        enabledByDefault = (
            "Yes" if (attributes & SE_PRIVILEGE_ENABLED_BY_DEFAULT) else "No"
        )
        # currentPrivInfo.UsedForAccess    = (attributes & windows.SE_PRIVILEGE_USED_FOR_ACCESS) > 0
        # currentPrivInfo.Enabled          = (attributes & windows.SE_PRIVILEGE_ENABLED) > 0
        enabled = "Enabled" if (attributes & SE_PRIVILEGE_ENABLED) else "Disabled"
        # currentPrivInfo.Removed          = (attributes & windows.SE_PRIVILEGE_REMOVED) > 0
        removed = "Yes" if (attributes & SE_PRIVILEGE_REMOVED) else "No"

        print(
            "%s%s%s%s%s"
            % (
                pad(priv_name, 40),
                pad(priv_desc, 52),
                pad(enabled, 10),
                pad(enabledByDefault, 10),
                pad(removed, 10),
            )
        )

    win_free(tokenInfoBuffer)

    # integrity, err = getProcessIntegrityLevel(tokenHandle)
    integrity = getProcessIntegrityLevel(tokenHandle)
    win_call("kernel32.dll", "CloseHandle", tokenHandle)

    print("\nIntegrity Level: " + integrity)


def main(*args):
    GetPrivs()


main()
