# linux_sysctl_audit - report the security-relevant kernel sysctls.
#
# Ported to Starlark from Furtex's edrs/sysctl_blind.c (read-only "show").
# Upstream project: https://github.com/MatheuZSecurity/Furtex (MIT License,
# Copyright (c) 2026 MatheuZ). See README.md in this directory for attribution.
#
# This is deliberately read-only. Changing these values is a defensive-blinding
# action, not recon, and several are irreversible without a reboot
# (modules_disabled); it belongs behind an explicit operator command.

CTLS = [
    {
        "path": "/proc/sys/kernel/dmesg_restrict",
        "desc": "1 = unprivileged processes cannot read the kernel ring buffer",
    },
    {
        "path": "/proc/sys/kernel/kptr_restrict",
        "desc": "2 = kernel pointers hidden from /proc/kallsyms and friends",
    },
    {
        "path": "/proc/sys/kernel/perf_event_paranoid",
        "desc": "3 = perf_event_open restricted (perf-based EDR loses visibility)",
    },
    {
        "path": "/proc/sys/kernel/yama/ptrace_scope",
        "desc": "2 = only CAP_SYS_PTRACE may ptrace another process",
    },
    {
        "path": "/proc/sys/kernel/unprivileged_bpf_disabled",
        "desc": "1 = CAP_BPF required for all BPF operations",
    },
    {
        "path": "/proc/sys/net/core/bpf_jit_harden",
        "desc": "2 = constant blinding for privileged BPF programs",
    },
    {
        "path": "/proc/sys/kernel/modules_disabled",
        "desc": "1 = no new kernel modules can be loaded (irreversible without reboot)",
    },
]


def main(*args):
    print("[*] security-relevant sysctls")
    print("")
    print(sprintf("%-44s %-8s %s", "sysctl", "value", "meaning"))
    print(sprintf("%-44s %-8s %s", "------", "-----", "-------"))
    for ctl in CTLS:
        val = read_file(ctl["path"], default="").strip()
        name = ctl["path"]
        if str_startswith(name, "/proc/sys/"):
            name = name[len("/proc/sys/"):]
        print(sprintf("%-44s %-8s %s", name, val or "N/A", ctl["desc"]))
    return "OK"
