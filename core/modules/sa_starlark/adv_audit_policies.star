# Starlark implementation of adv_audit_policies/entry.c

def write_byte(addr, offset, val):
    win_call("msvcrt.dll", "memset", addr + offset, val & 0xFF, 1)

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

def adv_audit_policies():
    print("Advanced Audit Policies:")
    print("===========================================================================")

    # GUID array for audit categories
    # AuditQuerySystemPolicy(pSubCategories, Count, &pAuditPolicy)
    policy_ptr_ptr = win_alloc(8)
    res = win_call("advapi32.dll", "AuditQuerySystemPolicy", 0, 0, policy_ptr_ptr)

    if res["r1"] != 0:
        err_code = res.get("err_code", 0)
        err_msg = res.get("error", "")
        win_free(policy_ptr_ptr)
        print("[-] AuditQuerySystemPolicy status %d (Error %d: %s)" % (res["r1"], err_code, err_msg))
        return "Fail"

    p_policy = read_ptr(policy_ptr_ptr, 0)
    win_free(policy_ptr_ptr)

    if p_policy != 0:
        win_call("advapi32.dll", "AuditFree", p_policy)

    print("Audit policies query executed successfully.")
    return "OK"

def main(*args):
    return adv_audit_policies()

main()
