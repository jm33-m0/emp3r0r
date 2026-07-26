# Starlark implementation for AD LDAP querying via dynamic FFI primitives


# Low-level memory writing helper functions
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
        char_val = ord(s[i : i + 1])
        write_byte(ptr, i * 2, char_val & 0xFF)
        write_byte(ptr, i * 2 + 1, (char_val >> 8) & 0xFF)
    write_byte(ptr, len(s) * 2, 0)
    write_byte(ptr, len(s) * 2 + 1, 0)
    return ptr


# Low-level binary memory reading helper functions
def read_uint32(addr, offset):
    data = win_read_mem(addr + offset, 4)
    return data[0] | (data[1] << 8) | (data[2] << 16) | (data[3] << 24)


def read_uint64(addr, offset):
    data = win_read_mem(addr + offset, 8)
    return (
        data[0]
        | (data[1] << 8)
        | (data[2] << 16)
        | (data[3] << 24)
        | (data[4] << 32)
        | (data[5] << 40)
        | (data[6] << 48)
        | (data[7] << 56)
    )


def read_ptr(addr, offset):
    return read_uint64(addr, offset)


def read_wstring(ptr):
    result = ""
    offset = 0
    for i in range(1024):
        data = win_read_mem(ptr + offset, 2)
        b0 = data[0]
        b1 = data[1]
        char_code = b0 | (b1 << 8)
        if char_code == 0:
            break
        result += chr(char_code)
        offset += 2
    return result


# Formatting capabilities for binary LDAP attributes
def to_hex(val, width):
    h = "0123456789abcdef"
    res = ""
    for i in range(width):
        res = h[val & 15] + res
        val >>= 4
    return res


def uuid_to_string(b):
    if len(b) < 16:
        return ""
    d1 = b[0] | (b[1] << 8) | (b[2] << 16) | (b[3] << 24)
    d2 = b[4] | (b[5] << 8)
    d3 = b[6] | (b[7] << 8)
    return (
        to_hex(d1, 8)
        + "-"
        + to_hex(d2, 4)
        + "-"
        + to_hex(d3, 4)
        + "-"
        + to_hex(b[8], 2)
        + to_hex(b[9], 2)
        + "-"
        + to_hex(b[10], 2)
        + to_hex(b[11], 2)
        + to_hex(b[12], 2)
        + to_hex(b[13], 2)
        + to_hex(b[14], 2)
        + to_hex(b[15], 2)
    )


def base64_encode(data_list):
    if len(data_list) == 0:
        return ""
    b64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    res = ""
    for i in range(0, len(data_list), 3):
        b1 = data_list[i]
        b2 = data_list[i + 1] if i + 1 < len(data_list) else 0
        b3 = data_list[i + 2] if i + 2 < len(data_list) else 0

        res += b64_chars[b1 >> 2]
        res += b64_chars[((b1 & 3) << 4) | (b2 >> 4)]
        if i + 1 < len(data_list):
            res += b64_chars[((b2 & 15) << 2) | (b3 >> 6)]
        else:
            res += "="
        if i + 2 < len(data_list):
            res += b64_chars[b3 & 63]
        else:
            res += "="
    return res


def sid_to_string(sid_ptr):
    str_ptr_ptr = win_alloc(8)
    win_call("advapi32.dll", "ConvertSidToStringSidW", sid_ptr, str_ptr_ptr)
    str_ptr = read_ptr(str_ptr_ptr, 0)
    res = ""
    if str_ptr != 0:
        res = read_wstring(str_ptr)
        win_call("kernel32.dll", "LocalFree", str_ptr)
    win_free(str_ptr_ptr)
    return res


# Active Directory infrastructure lookup capabilities
def get_dc_name():
    pdc_ptr = win_alloc(8)
    res = win_call("netapi32.dll", "DsGetDcNameW", 0, 0, 0, 0, 0, pdc_ptr)
    dc_name = ""
    if res["r1"] == 0:
        pdc = read_ptr(pdc_ptr, 0)
        if pdc != 0:
            name_ptr = read_ptr(pdc, 0)
            if name_ptr != 0:
                full_name = read_wstring(name_ptr)
                if full_name.startswith("\\\\"):
                    dc_name = full_name[2:]
                else:
                    dc_name = full_name
        win_call("netapi32.dll", "NetApiBufferFree", pdc)
    win_free(pdc_ptr)
    return dc_name


def get_domain_base_dn(ld):
    attr_name = "defaultNamingContext"
    attr_array = win_alloc(16)
    p_attr = create_utf16_string(attr_name)
    write_ptr(attr_array, 0, p_attr)
    write_ptr(attr_array, 8, 0)

    p_filter = create_utf16_string("(objectclass=*)")

    search_res = win_call(
        "wldap32.dll",
        "ldap_search_init_pageW",
        ld,
        0,
        0,
        p_filter,
        attr_array,
        0,
        0,
        0,
        15,
        1,
        0,
    )
    search_handle = search_res["r1"]

    dn = ""
    if search_handle != 0:
        timeout = win_alloc(8)
        write_uint32(timeout, 0, 10)
        page_count_ptr = win_alloc(4)
        result_ptr_ptr = win_alloc(8)

        stat = win_call(
            "wldap32.dll",
            "ldap_get_next_page_s",
            ld,
            search_handle,
            timeout,
            1,
            page_count_ptr,
            result_ptr_ptr,
        )["r1"]

        if stat == 0 or stat == 94:
            res_ptr = read_ptr(result_ptr_ptr, 0)
            if res_ptr != 0:
                entry = win_call("wldap32.dll", "ldap_first_entry", ld, res_ptr)["r1"]
                if entry != 0:
                    vals = win_call(
                        "wldap32.dll", "ldap_get_valuesW", ld, entry, p_attr
                    )["r1"]
                    if vals != 0:
                        val_ptr = read_ptr(vals, 0)
                        if val_ptr != 0:
                            dn = read_wstring(val_ptr)
                        win_call("wldap32.dll", "ldap_value_freeW", vals)
            if res_ptr != 0:
                win_call("wldap32.dll", "ldap_msgfree", res_ptr)

        win_call("wldap32.dll", "ldap_search_abandon_page", ld, search_handle)
        win_free(timeout)
        win_free(page_count_ptr)
        win_free(result_ptr_ptr)

    win_free(p_attr)
    win_free(attr_array)
    win_free(p_filter)
    return dn


def ldap_search(
    ldap_filter,
    ldap_attributes,
    results_count,
    scope_of_search,
    hostname,
    domain,
    ldaps,
):
    targetdc = hostname
    if not targetdc:
        targetdc = get_dc_name()
        if not targetdc:
            print("[-] Error: Failed to identify Domain Controller.")
            return

    port = 636 if ldaps else 389
    res = win_call("wldap32.dll", "ldap_initW", targetdc, port)
    ld = res["r1"]
    if ld == 0:
        print("[-] Error: Failed to establish LDAP connection on port " + str(port))
        return

    version_ptr = win_alloc(4)
    write_uint32(version_ptr, 0, 3)
    win_call("wldap32.dll", "ldap_set_optionW", ld, 0x11, version_ptr)

    if ldaps:
        win_call("wldap32.dll", "ldap_set_optionW", ld, 0x0A, 1)
    else:
        sign_ptr = win_alloc(8)
        write_ptr(sign_ptr, 0, 1)
        win_call("wldap32.dll", "ldap_set_optionW", ld, 0x95, sign_ptr)
        win_call("wldap32.dll", "ldap_set_optionW", ld, 0x96, sign_ptr)
        win_free(sign_ptr)

    res = win_call("wldap32.dll", "ldap_bind_sW", ld, 0, 0, 0x0486)
    if res["r1"] != 0:
        print("[-] Error: Bind failed with error code: " + str(res["r1"]))
        win_call("wldap32.dll", "ldap_unbind", ld)
        win_free(version_ptr)
        return

    dn = domain
    if not dn:
        dn = get_domain_base_dn(ld)

    if not dn:
        print("[-] Error: Failed to locate default naming context directory paths.")
        win_call("wldap32.dll", "ldap_unbind", ld)
        win_free(version_ptr)
        return

    scope = 0
    if scope_of_search == 2:
        scope = 1
    elif scope_of_search == 3:
        scope = 2

    attr_ptrs = []
    attr_array = 0
    server_controls = 0
    payload = 0
    oid_ptr = 0
    control_ptr = 0

    if ldap_attributes:
        attr_list = ldap_attributes.split(",")
        attr_array = win_alloc((len(attr_list) + 1) * 8)

        has_sd = False
        for i in range(len(attr_list)):
            if attr_list[i].lower() == "ntsecuritydescriptor":
                has_sd = True
            p = create_utf16_string(attr_list[i])
            attr_ptrs.append(p)
            write_ptr(attr_array, i * 8, p)
        write_ptr(attr_array, len(attr_list) * 8, 0)

        if has_sd:
            payload = win_alloc(5)
            write_byte(payload, 0, 0x30)
            write_byte(payload, 1, 0x03)
            write_byte(payload, 2, 0x02)
            write_byte(payload, 3, 0x01)
            write_byte(payload, 4, 0x07)

            control_ptr = win_alloc(32)
            oid_ptr = create_utf16_string("1.2.840.113556.1.4.801")
            write_ptr(control_ptr, 0, oid_ptr)
            write_uint32(control_ptr, 8, 5)
            write_ptr(control_ptr, 16, payload)
            write_byte(control_ptr, 24, 1)

            server_controls = win_alloc(16)
            write_ptr(server_controls, 0, control_ptr)
            write_ptr(server_controls, 8, 0)

    search_res = win_call(
        "wldap32.dll",
        "ldap_search_init_pageW",
        ld,
        dn,
        scope,
        ldap_filter,
        attr_array,
        0,
        server_controls,
        0,
        15,
        results_count,
        0,
    )
    search_handle = search_res["r1"]

    if search_handle == 0:
        print("[-] Error: Paging not supported on this server or search failed.")
    else:
        timeout = win_alloc(8)
        write_uint32(timeout, 0, 20)
        write_uint32(timeout, 4, 0)

        total_results = 0
        page_count_ptr = win_alloc(4)
        result_ptr_ptr = win_alloc(8)

        while True:
            limit = 64
            if results_count > 0 and (results_count - total_results) < 64:
                limit = results_count - total_results

            stat_res = win_call(
                "wldap32.dll",
                "ldap_get_next_page_s",
                ld,
                search_handle,
                timeout,
                limit,
                page_count_ptr,
                result_ptr_ptr,
            )
            stat = stat_res["r1"]

            if stat != 0 and stat != 94:
                print(
                    "[-] Error: ldap_get_next_page_s failed with status: " + str(stat)
                )
                break

            res_ptr = read_ptr(result_ptr_ptr, 0)
            if res_ptr == 0:
                break

            num_entries = win_call("wldap32.dll", "ldap_count_entries", ld, res_ptr)[
                "r1"
            ]
            if num_entries == 0xFFFFFFFF or num_entries == 0:
                win_call("wldap32.dll", "ldap_msgfree", res_ptr)
                break

            total_results += num_entries

            entry = win_call("wldap32.dll", "ldap_first_entry", ld, res_ptr)["r1"]
            while entry != 0:
                print("\n--------------------")

                # Fetch and print the unique entry Distinguished Name pathway explicitly
                dn_ptr = win_call("wldap32.dll", "ldap_get_dnW", ld, entry)["r1"]
                if dn_ptr != 0:
                    entry_dn = read_wstring(dn_ptr)
                    print("DN: " + entry_dn)
                    win_call("wldap32.dll", "ldap_memfreeW", dn_ptr)

                ber_ptr = win_alloc(8)
                attr = win_call(
                    "wldap32.dll", "ldap_first_attributeW", ld, entry, ber_ptr
                )["r1"]
                while attr != 0:
                    attr_name = read_wstring(attr)
                    attr_lower = attr_name.lower()

                    is_binary = False
                    binary_fields = [
                        "pkiexpirationperiod",
                        "pkioverlapperiod",
                        "cacertificate",
                        "objectsid",
                        "securityidentifier",
                        "objectguid",
                        "ntsecuritydescriptor",
                        "msds-generationid",
                        "auditingpolicy",
                        "dsasignature",
                        "ms-ds-creatorsid",
                        "logonhours",
                        "schemaidguid",
                        "msds-allowedtoactonbehalfofotheridentity",
                        "msmqdigests",
                        "msmqsigncertificates",
                        "usercertificate",
                        "attributesecurityguid",
                        "dnsrecord",
                    ]

                    if attr_lower in binary_fields:
                        is_binary = True

                    if is_binary:
                        vals = win_call(
                            "wldap32.dll", "ldap_get_values_lenW", ld, entry, attr
                        )["r1"]
                        if vals != 0:
                            out_str = attr_name + ": "
                            i = 0
                            while True:
                                bval_ptr = read_ptr(vals, i * 8)
                                if bval_ptr == 0:
                                    break
                                bv_len = read_uint32(bval_ptr, 0)
                                bv_val = read_ptr(bval_ptr, 8)
                                raw_bytes = win_read_mem(bv_val, bv_len)

                                val_str = ""
                                if (
                                    attr_lower == "objectguid"
                                    or attr_lower == "schemaidguid"
                                    or attr_lower == "attributesecurityguid"
                                ):
                                    val_str = uuid_to_string(raw_bytes)
                                elif (
                                    attr_lower == "objectsid"
                                    or attr_lower == "securityidentifier"
                                    or attr_lower == "ms-ds-creatorsid"
                                ):
                                    val_str = sid_to_string(bv_val)
                                else:
                                    val_str = base64_encode(raw_bytes)

                                if i > 0:
                                    out_str += ", "
                                out_str += val_str
                                i += 1
                            print(out_str)
                            win_call("wldap32.dll", "ldap_value_free_len", vals)
                    else:
                        vals = win_call(
                            "wldap32.dll", "ldap_get_valuesW", ld, entry, attr
                        )["r1"]
                        if vals != 0:
                            out_str = attr_name + ": "
                            i = 0
                            while True:
                                val_ptr = read_ptr(vals, i * 8)
                                if val_ptr == 0:
                                    break
                                val_str = read_wstring(val_ptr)
                                if i > 0:
                                    out_str += ", "
                                out_str += val_str
                                i += 1
                            print(out_str)
                            win_call("wldap32.dll", "ldap_value_freeW", vals)

                    win_call("wldap32.dll", "ldap_memfreeW", attr)
                    attr = win_call(
                        "wldap32.dll",
                        "ldap_next_attributeW",
                        ld,
                        entry,
                        read_ptr(ber_ptr, 0),
                    )["r1"]

                if read_ptr(ber_ptr, 0) != 0:
                    win_call("wldap32.dll", "ber_free", read_ptr(ber_ptr, 0), 0)
                win_free(ber_ptr)
                entry = win_call("wldap32.dll", "ldap_next_entry", ld, entry)["r1"]

            win_call("wldap32.dll", "ldap_msgfree", res_ptr)

            if stat == 94:
                break

            if results_count != 0 and total_results >= results_count:
                break

        print("\n[+] Total entries retrieved: " + str(total_results))
        win_call("wldap32.dll", "ldap_search_abandon_page", ld, search_handle)

        win_free(timeout)
        win_free(page_count_ptr)
        win_free(result_ptr_ptr)

    win_call("wldap32.dll", "ldap_unbind", ld)
    win_free(version_ptr)

    for p in attr_ptrs:
        win_free(p)
    if attr_array != 0:
        win_free(attr_array)

    if server_controls != 0:
        win_free(payload)
        win_free(oid_ptr)
        win_free(control_ptr)
        win_free(server_controls)


def main(*args):
    ldap_filter = args[0] if len(args) > 0 else "(objectclass=*)"
    ldap_attributes = args[1] if len(args) > 1 else ""
    results_count = int(args[2]) if len(args) > 2 else 0
    scope_of_search = int(args[3]) if len(args) > 3 else 0
    hostname = args[4] if len(args) > 4 else ""
    domain = args[5] if len(args) > 5 else ""
    ldaps_input = args[6] if len(args) > 6 else False

    if (
        str(hostname).lower() == "false"
        or str(hostname).lower() == "none"
        or hostname == False
    ):
        hostname = ""
    if (
        str(domain).lower() == "false"
        or str(domain).lower() == "none"
        or domain == False
    ):
        domain = ""

    ldaps = False
    if ldaps_input == True or ldaps_input == 1 or str(ldaps_input).lower() == "true":
        ldaps = True

    ldap_search(
        ldap_filter,
        ldap_attributes,
        results_count,
        scope_of_search,
        hostname,
        domain,
        ldaps,
    )
