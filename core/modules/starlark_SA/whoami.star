# Starlark implementation of whoami parsing low level primitives

# Windows Token Attribute Constants
SE_GROUP_MANDATORY          = 0x00000001
SE_GROUP_ENABLED_BY_DEFAULT = 0x00000002
SE_GROUP_ENABLED            = 0x00000004
SE_GROUP_OWNER              = 0x00000008
SE_GROUP_LOGON_ID           = 0xC0000000

SE_PRIVILEGE_ENABLED        = 0x00000002

# SID Use Mapping Constants
SidTypeUser           = 1
SidTypeGroup          = 2
SidTypeDomain         = 3
SidTypeAlias          = 4
SidTypeWellKnownGroup = 5
SidTypeDeletedAccount = 6
SidTypeInvalid        = 7
SidTypeUnknown        = 8
SidTypeComputer       = 9
SidTypeLabel          = 10


# Low-level Windows API wrapper abstractions
def get_current_token():
    res = win_call("kernel32.dll", "GetCurrentProcess")
    h_process = res["r1"]
    
    h_token_ptr = win_alloc(8)
    TOKEN_QUERY = 0x0008
    res = win_call("advapi32.dll", "OpenProcessToken", h_process, TOKEN_QUERY, h_token_ptr)
    if res["r1"] == 0:
        win_free(h_token_ptr)
        return 0
        
    h_token = read_ptr(h_token_ptr, 0)
    win_free(h_token_ptr)
    return h_token

def lookup_account_sid_ffi(sid_ptr):
    cch_name_ptr = win_alloc(4)
    cch_domain_ptr = win_alloc(4)
    pe_use_ptr = win_alloc(4)
    
    win_call("advapi32.dll", "LookupAccountSidW", 0, sid_ptr, 0, cch_name_ptr, 0, cch_domain_ptr, pe_use_ptr)
    
    name_size = read_uint32(cch_name_ptr, 0)
    domain_size = read_uint32(cch_domain_ptr, 0)
    
    if name_size == 0:
        name_size = 256
    if domain_size == 0:
        domain_size = 256
        
    name_buf = win_alloc(name_size * 2)
    domain_buf = win_alloc(domain_size * 2)
    
    res = win_call("advapi32.dll", "LookupAccountSidW", 0, sid_ptr, name_buf, cch_name_ptr, domain_buf, cch_domain_ptr, pe_use_ptr)
    
    account = ""
    domain = ""
    use = 0
    if res["r1"] != 0:
        account = read_wstring(name_buf)
        domain = read_wstring(domain_buf)
        use = read_uint32(pe_use_ptr, 0)
        
    win_free(cch_name_ptr)
    win_free(cch_domain_ptr)
    win_free(pe_use_ptr)
    win_free(name_buf)
    win_free(domain_buf)
    
    return {"account": account, "domain": domain, "use": use}

def lookup_privilege_name_ffi(luid_ptr):
    cch_name_ptr = win_alloc(4)
    win_call("advapi32.dll", "LookupPrivilegeNameW", 0, luid_ptr, 0, cch_name_ptr)
    
    name_size = read_uint32(cch_name_ptr, 0)
    if name_size == 0:
        name_size = 256
        
    name_buf = win_alloc(name_size * 2)
    res = win_call("advapi32.dll", "LookupPrivilegeNameW", 0, luid_ptr, name_buf, cch_name_ptr)
    
    priv_name = "Unknown"
    if res["r1"] != 0:
        priv_name = read_wstring(name_buf)
        
    win_free(cch_name_ptr)
    win_free(name_buf)
    return priv_name

def pad(text, width):
    text = str(text)
    if len(text) >= width:
        return text
    return text + " " * (width - len(text))

def parse_group_attributes(attrs):
    if attrs == 0x60:
        attrs = 0x07
    
    result = ""
    if attrs & SE_GROUP_MANDATORY:
        result += "Mandatory group, "
    if attrs & SE_GROUP_ENABLED_BY_DEFAULT:
        result += "Enabled by default, "
    if attrs & SE_GROUP_ENABLED:
        result += "Enabled group, "
    if attrs & SE_GROUP_OWNER:
        result += "Group owner, "
    return result

def get_sid_type_string(use_type):
    if use_type == SidTypeWellKnownGroup:
        return "Well-known group"
    if use_type == SidTypeAlias:
        return "Alias"
    if use_type == SidTypeLabel:
        return "Label"
    if use_type == SidTypeGroup:
        return "Group"
    return "User"

def do_whoami_user():
    h_token = get_current_token()
    if h_token == 0:
        return
        
    TOKEN_INFORMATION_CLASS_TokenUser = 1
    req_size_ptr = win_alloc(4)
    win_call("advapi32.dll", "GetTokenInformation", h_token, TOKEN_INFORMATION_CLASS_TokenUser, 0, 0, req_size_ptr)
    req_size = read_uint32(req_size_ptr, 0)
    
    token_user_buf = win_alloc(req_size)
    win_call("advapi32.dll", "GetTokenInformation", h_token, TOKEN_INFORMATION_CLASS_TokenUser, token_user_buf, req_size, req_size_ptr)
    win_free(req_size_ptr)
    
    user_sid_ptr = read_ptr(token_user_buf, 0)
    
    str_sid_ptr_ptr = win_alloc(8)
    win_call("advapi32.dll", "ConvertSidToStringSidW", user_sid_ptr, str_sid_ptr_ptr)
    str_sid_ptr = read_ptr(str_sid_ptr_ptr, 0)
    win_free(str_sid_ptr_ptr)
    
    user_sid_str = ""
    if str_sid_ptr != 0:
        user_sid_str = read_wstring(str_sid_ptr)
        win_call("kernel32.dll", "LocalFree", str_sid_ptr)
        
    lookup = lookup_account_sid_ffi(user_sid_ptr)
    win_free(token_user_buf)
    win_call("kernel32.dll", "CloseHandle", h_token)
    
    full_name = (lookup["domain"] + "\\" + lookup["account"]) if lookup["domain"] else lookup["account"]
    
    print("\nUserName\t\tSID")
    print("====================== ====================================")
    print("%s\t%s\n" % (full_name, user_sid_str))

def do_whoami_groups():
    print("\n%s%s%s%s" % (pad("GROUP INFORMATION", 50), pad("Type", 25), pad("SID", 45), pad("Attributes", 25)))
    print("================================================= ===================== ============================================= ==================================================")
    
    h_token = get_current_token()
    if h_token == 0:
        return
        
    TOKEN_INFORMATION_CLASS_TokenGroups = 2
    req_size_ptr = win_alloc(4)
    win_call("advapi32.dll", "GetTokenInformation", h_token, TOKEN_INFORMATION_CLASS_TokenGroups, 0, 0, req_size_ptr)
    req_size = read_uint32(req_size_ptr, 0)
    
    token_groups_buf = win_alloc(req_size)
    win_call("advapi32.dll", "GetTokenInformation", h_token, TOKEN_INFORMATION_CLASS_TokenGroups, token_groups_buf, req_size, req_size_ptr)
    win_free(req_size_ptr)
    
    group_count = read_uint32(token_groups_buf, 0)
    
    offset = 8
    for i in range(group_count):
        group_sid_ptr = read_ptr(token_groups_buf, offset)
        attrs = read_uint32(token_groups_buf, offset + 8)
        offset += 16
        
        if attrs & SE_GROUP_LOGON_ID:
            continue
            
        lookup = lookup_account_sid_ffi(group_sid_ptr)
        if not lookup["account"]:
            continue
            
        str_sid_ptr_ptr = win_alloc(8)
        win_call("advapi32.dll", "ConvertSidToStringSidW", group_sid_ptr, str_sid_ptr_ptr)
        str_sid_ptr = read_ptr(str_sid_ptr_ptr, 0)
        win_free(str_sid_ptr_ptr)
        
        sid_str = ""
        if str_sid_ptr != 0:
            sid_str = read_wstring(str_sid_ptr)
            win_call("kernel32.dll", "LocalFree", str_sid_ptr)
            
        name_str = lookup["account"]
        if lookup["domain"]:
            name_str = lookup["domain"] + "\\" + lookup["account"]
            
        type_str = get_sid_type_string(lookup["use"])
        attr_str = parse_group_attributes(attrs)
        
        print("%s%s%s%s" % (pad(name_str, 50), pad(type_str, 25), pad(sid_str, 45), pad(attr_str, 25)))
        
    win_free(token_groups_buf)
    win_call("kernel32.dll", "CloseHandle", h_token)

def do_whoami_privs():
    print("\n%s%s%s" % (pad("Privilege Name", 30), pad("Description", 50), pad("State", 30)))
    print("============================= ================================================= ===========================")
    
    h_token = get_current_token()
    if h_token == 0:
        return
        
    TOKEN_INFORMATION_CLASS_TokenPrivileges = 3
    req_size_ptr = win_alloc(4)
    win_call("advapi32.dll", "GetTokenInformation", h_token, TOKEN_INFORMATION_CLASS_TokenPrivileges, 0, 0, req_size_ptr)
    req_size = read_uint32(req_size_ptr, 0)
    
    token_privs_buf = win_alloc(req_size)
    win_call("advapi32.dll", "GetTokenInformation", h_token, TOKEN_INFORMATION_CLASS_TokenPrivileges, token_privs_buf, req_size, req_size_ptr)
    win_free(req_size_ptr)
    
    priv_count = read_uint32(token_privs_buf, 0)
    
    offset = 4
    for i in range(priv_count):
        luid_address = token_privs_buf + offset
        attrs = read_uint32(token_privs_buf, offset + 8)
        offset += 12
        
        name = lookup_privilege_name_ffi(luid_address)
        
        state_str = "Disabled"
        if attrs & SE_PRIVILEGE_ENABLED:
            state_str = "Enabled"
            
        print("%s%s%s" % (pad(name, 30), pad("Access token privilege", 50), pad(state_str, 30)))
        
    win_free(token_privs_buf)
    win_call("kernel32.dll", "CloseHandle", h_token)

def main(*args):
    do_whoami_user()
    do_whoami_groups()
    do_whoami_privs()

main()
