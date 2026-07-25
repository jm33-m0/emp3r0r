# Starlark translation of CurrentTokenOwner() + TokenOwner() from priv_windows.go
#
# func CurrentTokenOwner() (string, error) {
#     currToken := CurrentToken
#     if currToken == 0 { currToken = windows.GetCurrentProcessToken() }
#     return TokenOwner(currToken)
# }
#
# func TokenOwner(hToken windows.Token) (string, error) {
#     tokenUser, err := hToken.GetTokenUser()
#     user, domain, _, err := tokenUser.User.Sid.LookupAccount("")
#     return fmt.Sprintf("%s\\%s", domain, user), err
# }


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


# ── TokenOwner ────────────────────────────────────────────────────────────────
def TokenOwner(hToken):
    """
    func TokenOwner(hToken windows.Token) (string, error)
    Calls GetTokenInformation(TokenUser) then LookupAccountSidW to resolve
    the token's SID to a "DOMAIN\\user" string.
    """
    # tokenUser, err := hToken.GetTokenUser()
    # → windows.GetTokenInformation(hToken, windows.TokenUser, ...)
    TokenUser = 1  # windows.TokenUser

    # First call: determine required buffer size
    sizePtr = win_alloc(4)
    win_call("advapi32.dll", "GetTokenInformation", hToken, TokenUser, 0, 0, sizePtr)
    bufSize = read_uint32(sizePtr, 0)
    win_free(sizePtr)

    if bufSize == 0:
        return ""

    # tokenUser buffer: SID_AND_ATTRIBUTES { Sid *SID, Attributes DWORD }
    tokenUserBuf = win_alloc(bufSize)
    sizePtr2 = win_alloc(4)
    res = win_call(
        "advapi32.dll",
        "GetTokenInformation",
        hToken,
        TokenUser,
        tokenUserBuf,
        bufSize,
        sizePtr2,
    )
    win_free(sizePtr2)

    if res["r1"] == 0:
        win_free(tokenUserBuf)
        err_code = res.get("err_code", 0)
        err_msg = res.get("error", "")
        if err_code != 0 or err_msg != "":
            print("[-] GetTokenInformation failed. Error %d: %s" % (err_code, err_msg))
        return ""

    # tokenUser.User.Sid  →  first pointer in SID_AND_ATTRIBUTES
    sid_ptr = read_ptr(tokenUserBuf, 0)
    win_free(tokenUserBuf)

    # user, domain, _, err := tokenUser.User.Sid.LookupAccount("")
    # → LookupAccountSidW(nil, sid, name, &nameSize, domain, &domainSize, &peUse)
    # First call with NULL buffers to get required sizes
    cchName_ptr = win_alloc(4)
    cchDomain_ptr = win_alloc(4)
    peUse_ptr = win_alloc(4)
    win_call(
        "advapi32.dll",
        "LookupAccountSidW",
        0,
        sid_ptr,
        0,
        cchName_ptr,
        0,
        cchDomain_ptr,
        peUse_ptr,
    )

    nameSize = read_uint32(cchName_ptr, 0)
    domainSize = read_uint32(cchDomain_ptr, 0)
    if nameSize == 0:
        nameSize = 256
    if domainSize == 0:
        domainSize = 256

    nameBuf = win_alloc(nameSize * 2)
    domainBuf = win_alloc(domainSize * 2)

    res = win_call(
        "advapi32.dll",
        "LookupAccountSidW",
        0,
        sid_ptr,
        nameBuf,
        cchName_ptr,
        domainBuf,
        cchDomain_ptr,
        peUse_ptr,
    )

    user = ""
    domain = ""
    if res["r1"] != 0:
        user = read_wstring(nameBuf)
        domain = read_wstring(domainBuf)

    win_free(cchName_ptr)
    win_free(cchDomain_ptr)
    win_free(peUse_ptr)
    win_free(nameBuf)
    win_free(domainBuf)

    # return fmt.Sprintf("%s\\%s", domain, user), err
    return domain + "\\" + user


# ── CurrentTokenOwner ─────────────────────────────────────────────────────────
def CurrentTokenOwner():
    """
    func CurrentTokenOwner() (string, error) {
        currToken := CurrentToken
        if currToken == 0 {
            currToken = windows.GetCurrentProcessToken()
        }
        return TokenOwner(currToken)
    }

    windows.GetCurrentProcessToken() returns the pseudo-handle -4
    (0xFFFFFFFFFFFFFFFC on x64).  No API call is made – it is a constant.
    """
    # currToken := CurrentToken
    # Since Starlark modules are stateless across invocations, CurrentToken is
    # always 0 here, so we always use windows.GetCurrentProcessToken().
    currToken = 0

    # if currToken == 0 { currToken = windows.GetCurrentProcessToken() }
    # windows.GetCurrentProcessToken() is the pseudo-handle -4 (no syscall needed)
    CURRENT_PROCESS_TOKEN_PSEUDO_HANDLE = 0xFFFFFFFFFFFFFFFC  # -4 as uint64
    if currToken == 0:
        currToken = CURRENT_PROCESS_TOKEN_PSEUDO_HANDLE

    # return TokenOwner(currToken)
    return TokenOwner(currToken)


def main(*args):
    owner = CurrentTokenOwner()
    if owner:
        print("[+] Current token owner: " + owner)
    else:
        print("[-] Could not resolve current token owner.")


main()
