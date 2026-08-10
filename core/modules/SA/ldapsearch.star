# Starlark LDAP search — mirrors CS-Situational-Awareness-BOF ldapsearch/entry.c
# win_call auto-converts Python strings to UTF-16, so we use -W variants throughout.

def write_byte(addr, offset, val):
    win_call("msvcrt.dll", "memset", addr + offset, val, 1)

def write_uint32(addr, offset, val):
    write_byte(addr, offset, val & 0xFF)
    write_byte(addr, offset + 1, (val >> 8) & 0xFF)
    write_byte(addr, offset + 2, (val >> 16) & 0xFF)
    write_byte(addr, offset + 3, (val >> 24) & 0xFF)

def write_ptr(addr, offset, val):
    write_uint32(addr, offset, val & 0xFFFFFFFF)
    write_uint32(addr, offset + 4, (val >> 32) & 0xFFFFFFFF)

def create_utf16_string(s):
    ptr = win_alloc((len(s) + 1) * 2)
    for i in range(len(s)):
        c = ord(s[i : i + 1])
        write_byte(ptr, i * 2, c & 0xFF)
        write_byte(ptr, i * 2 + 1, (c >> 8) & 0xFF)
    write_byte(ptr, len(s) * 2, 0)
    write_byte(ptr, len(s) * 2 + 1, 0)
    return ptr

def read_uint32(addr, offset):
    d = win_read_mem(addr + offset, 4)
    return d[0] | (d[1] << 8) | (d[2] << 16) | (d[3] << 24)

def read_uint64(addr, offset):
    d = win_read_mem(addr + offset, 8)
    return d[0] | (d[1] << 8) | (d[2] << 16) | (d[3] << 24) | (d[4] << 32) | (d[5] << 40) | (d[6] << 48) | (d[7] << 56)

def read_ptr(addr, offset):
    return read_uint64(addr, offset)

def read_wstring(ptr):
    result = ""
    off = 0
    for _ in range(1024):
        d = win_read_mem(ptr + off, 2)
        ch = d[0] | (d[1] << 8)
        if ch == 0:
            break
        result += chr(ch)
        off += 2
    return result

def base64_encode(data_list):
    if len(data_list) == 0:
        return ""
    t = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    res = ""
    for i in range(0, len(data_list), 3):
        b1 = data_list[i]
        b2 = data_list[i + 1] if i + 1 < len(data_list) else 0
        b3 = data_list[i + 2] if i + 2 < len(data_list) else 0
        res += t[b1 >> 2]
        res += t[((b1 & 3) << 4) | (b2 >> 4)]
        res += "=" if i + 1 >= len(data_list) else t[((b2 & 15) << 2) | (b3 >> 6)]
        res += "=" if i + 2 >= len(data_list) else t[b3 & 63]
    return res

def sid_to_string(sid_ptr):
    pp = win_alloc(8)
    win_call("advapi32.dll", "ConvertSidToStringSidW", sid_ptr, pp)
    p = read_ptr(pp, 0)
    res = ""
    if p != 0:
        res = read_wstring(p)
        win_call("kernel32.dll", "LocalFree", p)
    win_free(pp)
    return res

def guid_to_string(uuid_ptr):
    pp = win_alloc(8)
    win_call("rpcrt4.dll", "UuidToStringW", uuid_ptr, pp)
    p = read_ptr(pp, 0)
    res = ""
    if p != 0:
        res = read_wstring(p)
        win_call("rpcrt4.dll", "RpcStringFreeW", pp)
    win_free(pp)
    return res

def get_dc_name():
    pp = win_alloc(8)
    r = win_call("netapi32.dll", "DsGetDcNameW", 0, 0, 0, 0, 0, pp)
    dc = ""
    if r["r1"] == 0:
        pdc = read_ptr(pp, 0)
        if pdc != 0:
            np = read_ptr(pdc, 0)
            if np != 0:
                name = read_wstring(np)
                dc = name[2:] if name[:2] == "\\\\" else name
        win_call("netapi32.dll", "NetApiBufferFree", pdc)
    win_free(pp)
    return dc

def get_domain_base_dn():
    sz = 1024
    buf = win_alloc(sz * 2)
    sp = win_alloc(4)
    write_uint32(sp, 0, sz)
    r = win_call("secur32.dll", "GetUserNameExW", 1, buf, sp)
    dn = ""
    if r["r1"] != 0:
        full = read_wstring(buf)
        pos = full.find("DC=")
        if pos != -1:
            dn = full[pos:]
    win_free(buf)
    win_free(sp)
    return dn

def create_server_cert_callback():
    cb = win_alloc(16)
    op = win_alloc(4)
    write_byte(cb, 0, 0xB0)
    write_byte(cb, 1, 0x01)
    write_byte(cb, 2, 0xC3)
    win_call("kernel32.dll", "VirtualProtect", cb, 16, 0x20, op)
    win_free(op)
    return cb

def build_sd_flags_control():
    payload = win_alloc(5)
    write_byte(payload, 0, 0x30)
    write_byte(payload, 1, 0x03)
    write_byte(payload, 2, 0x02)
    write_byte(payload, 3, 0x01)
    write_byte(payload, 4, 0x07)
    ctrl = win_alloc(32)
    oid = create_utf16_string("1.2.840.113556.1.4.801")
    write_ptr(ctrl, 0, oid)
    write_uint32(ctrl, 8, 5)
    write_ptr(ctrl, 16, payload)
    write_byte(ctrl, 24, 1)
    return ctrl, payload, oid

def ldap_search(ldap_filter, ldap_attributes, results_count, scope_of_search, hostname, domain, ldaps):
    # Get DN first (matching BOF flow)
    dn = domain if domain else get_domain_base_dn()
    if not dn:
        print("[-] Failed to retrieve distinguished name.")
        return
    print("[*] Distinguished name: " + dn)

    # Get DC
    target = hostname if hostname else get_dc_name()
    if not target:
        print("[-] Failed to identify Domain Controller.")
        return
    port = 636 if ldaps else 389
    print("[*] targeting DC: " + target)
    print("[*] Binding to " + target)

    # ldap_initW — win_call auto-converts target string to UTF-16
    r = win_call("wldap32.dll", "ldap_initW", target, port)
    ld = r["r1"]
    if ld == 0:
        print("[-] Failed to establish LDAP connection on port " + str(port))
        return

    # Set LDAP version
    ver = win_alloc(4)
    write_uint32(ver, 0, 3)
    win_call("wldap32.dll", "ldap_set_optionW", ld, 0x11, ver)

    # Signing/sealing (or SSL) — keep sign_ptr alive through bind!
    cert_cb = 0
    sign_ptr = 0
    if ldaps:
        win_call("wldap32.dll", "ldap_set_optionW", ld, 0x0A, 1)
        cert_cb = create_server_cert_callback()
        win_call("wldap32.dll", "ldap_set_optionW", ld, 0x81, cert_cb)
    else:
        sign_ptr = win_alloc(8)
        write_ptr(sign_ptr, 0, 1)
        win_call("wldap32.dll", "ldap_set_optionW", ld, 0x95, sign_ptr)
        win_call("wldap32.dll", "ldap_set_optionW", ld, 0x96, sign_ptr)

    # Bind with DN — win_call auto-converts dn string to UTF-16
    r = win_call("wldap32.dll", "ldap_bind_sW", ld, dn, 0, 0x0486)
    if sign_ptr != 0:
        win_free(sign_ptr)  # safe now — bind has consumed option values

    if r["r1"] != 0:
        print("[-] Bind Failed with error: " + str(r["r1"]))
        win_call("wldap32.dll", "ldap_unbind", ld)
        win_free(ver)
        if cert_cb != 0:
            win_free(cert_cb)
        return
    print("[+] Successfully bound to LDAP server")

    # Scope mapping
    if scope_of_search == 1:
        scope = 0
    elif scope_of_search == 2:
        scope = 1
    else:
        scope = 2  # SUBTREE default

    print("[*] Filter: " + ldap_filter)

    # Build attribute array + SD control
    attr_ptrs = []
    attr_array = 0
    server_controls = 0
    srv_ctrl_array = 0

    if ldap_attributes:
        attrs = ldap_attributes.split(",")
        attr_array = win_alloc((len(attrs) + 1) * 8)
        has_sd = False
        for i in range(len(attrs)):
            a = attrs[i].strip()
            if a.lower() == "ntsecuritydescriptor":
                has_sd = True
            p = create_utf16_string(a)
            attr_ptrs.append(p)
            write_ptr(attr_array, i * 8, p)
        write_ptr(attr_array, len(attrs) * 8, 0)

        if has_sd:
            ctrl, payload, oid = build_sd_flags_control()
            attr_ptrs.extend([oid, payload, ctrl])
            srv_ctrl_array = win_alloc(16)
            write_ptr(srv_ctrl_array, 0, ctrl)
            write_ptr(srv_ctrl_array, 8, 0)
            server_controls = srv_ctrl_array

    # Paged search
    r = win_call("wldap32.dll", "ldap_search_init_pageW", ld, dn, scope,
                 ldap_filter, attr_array, 0, server_controls, 0, 15, results_count, 0)
    ph = r["r1"]

    if ph == 0:
        print("[-] Paging not supported on this server, aborting")
    else:
        timeout = win_alloc(8)
        write_uint32(timeout, 0, 20)
        total = 0
        pcp = win_alloc(4)
        rpp = win_alloc(8)

        while True:
            limit = 64
            if results_count > 0 and (results_count - total) < 64:
                limit = results_count - total

            sr = win_call("wldap32.dll", "ldap_get_next_page_s", ld, ph, timeout, limit, pcp, rpp)
            stat = sr["r1"]
            if stat != 0 and stat != 94:
                print("[-] ldap_get_next_page_s failed: " + str(stat))
                break

            res_ptr = read_ptr(rpp, 0)
            if res_ptr == 0:
                break

            n = win_call("wldap32.dll", "ldap_count_entries", ld, res_ptr)["r1"]
            if n == 0xFFFFFFFF or n == 0:
                win_call("wldap32.dll", "ldap_msgfree", res_ptr)
                break

            total += n

            entry = win_call("wldap32.dll", "ldap_first_entry", ld, res_ptr)["r1"]
            while entry != 0:
                print("\n--------------------")
                bp = win_alloc(8)
                attr = win_call("wldap32.dll", "ldap_first_attributeW", ld, entry, bp)["r1"]

                while attr != 0:
                    aname = read_wstring(attr)
                    alow = aname.lower()

                    binary_f = [
                        "pkiexpirationperiod","pkioverlapperiod","cacertificate",
                        "objectsid","securityidentifier","objectguid","ntsecuritydescriptor",
                        "msds-generationid","auditingpolicy","dsasignature","ms-ds-creatorsid",
                        "logonhours","schemaidguid","msds-allowedtoactonbehalfofotheridentity",
                        "msmqdigests","msmqsigncertificates","usercertificate",
                        "attributesecurityguid","dnsrecord",
                    ]
                    is_bin = alow in binary_f

                    if is_bin:
                        vals = win_call("wldap32.dll", "ldap_get_values_lenW", ld, entry, attr)["r1"]
                        if vals != 0:
                            out = aname + ": "
                            j = 0
                            while True:
                                bvp = read_ptr(vals, j * 8)
                                if bvp == 0:
                                    break
                                bv_len = read_uint32(bvp, 0)
                                bv_val = read_ptr(bvp, 8)
                                raw = win_read_mem(bv_val, bv_len)

                                if alow in ("objectguid", "schemaidguid", "attributesecurityguid"):
                                    vs = guid_to_string(bv_val)
                                elif alow in ("objectsid", "securityidentifier", "ms-ds-creatorsid"):
                                    vs = sid_to_string(bv_val)
                                else:
                                    vs = base64_encode(raw)

                                if j > 0:
                                    out += ", "
                                out += vs
                                j += 1
                            print(out)
                            win_call("wldap32.dll", "ldap_value_free_len", vals)
                    else:
                        vals = win_call("wldap32.dll", "ldap_get_valuesW", ld, entry, attr)["r1"]
                        if vals != 0:
                            out = aname + ": "
                            j = 0
                            while True:
                                vp = read_ptr(vals, j * 8)
                                if vp == 0:
                                    break
                                vs = read_wstring(vp)
                                if j > 0:
                                    out += ", "
                                out += vs
                                j += 1
                            print(out)
                            win_call("wldap32.dll", "ldap_value_freeW", vals)

                    win_call("wldap32.dll", "ldap_memfreeW", attr)
                    attr = win_call("wldap32.dll", "ldap_next_attributeW", ld, entry, read_ptr(bp, 0))["r1"]

                bv = read_ptr(bp, 0)
                if bv != 0:
                    win_call("wldap32.dll", "ber_free", bv, 0)
                win_free(bp)
                entry = win_call("wldap32.dll", "ldap_next_entry", ld, entry)["r1"]

            win_call("wldap32.dll", "ldap_msgfree", res_ptr)
            if stat == 94:
                break
            if results_count != 0 and total >= results_count:
                break

        print("\n[+] Total entries retrieved: " + str(total))
        win_call("wldap32.dll", "ldap_search_abandon_page", ld, ph)
        win_free(timeout)
        win_free(pcp)
        win_free(rpp)

    # Cleanup
    win_call("wldap32.dll", "ldap_unbind", ld)
    win_free(ver)
    if cert_cb != 0:
        win_free(cert_cb)
    for p in attr_ptrs:
        win_free(p)
    if attr_array != 0:
        win_free(attr_array)
    if srv_ctrl_array != 0:
        win_free(srv_ctrl_array)

def main(*args):
    f = args[0] if len(args) > 0 else "(objectclass=*)"
    a = args[1] if len(args) > 1 else ""
    c = int(args[2]) if len(args) > 2 else 0
    s = int(args[3]) if len(args) > 3 else 3
    h = args[4] if len(args) > 4 else ""
    d = args[5] if len(args) > 5 else ""
    l = args[6] if len(args) > 6 else False

    if str(h).lower() in ("false", "none") or h == False:
        h = ""
    if str(d).lower() in ("false", "none") or d == False:
        d = ""
    ldaps = l == True or l == 1 or str(l).lower() == "true"

    ldap_search(f, a, c, s, h, d, ldaps)
