# Starlark implementation of adv_audit_policies/entry.c


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

