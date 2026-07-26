CAPABILITIES = [
    "CAP_CHOWN",
    "CAP_DAC_OVERRIDE",
    "CAP_DAC_READ_SEARCH",
    "CAP_FOWNER",
    "CAP_FSETID",
    "CAP_KILL",
    "CAP_SETGID",
    "CAP_SETUID",
    "CAP_SETPCAP",
    "CAP_LINUX_IMMUTABLE",
    "CAP_NET_BIND_SERVICE",
    "CAP_NET_BROADCAST",
    "CAP_NET_ADMIN",
    "CAP_NET_RAW",
    "CAP_IPC_LOCK",
    "CAP_IPC_OWNER",
    "CAP_SYS_MODULE",
    "CAP_SYS_RAWIO",
    "CAP_SYS_CHROOT",
    "CAP_SYS_PTRACE",
    "CAP_SYS_PACCT",
    "CAP_SYS_ADMIN",
    "CAP_SYS_BOOT",
    "CAP_SYS_NICE",
    "CAP_SYS_RESOURCE",
    "CAP_SYS_TIME",
    "CAP_SYS_TTY_CONFIG",
    "CAP_MKNOD",
    "CAP_LEASE",
    "CAP_AUDIT_WRITE",
    "CAP_AUDIT_CONTROL",
    "CAP_SETFCAP",
    "CAP_MAC_OVERRIDE",
    "CAP_MAC_ADMIN",
    "CAP_SYSLOG",
    "CAP_WAKE_ALARM",
    "CAP_BLOCK_SUSPEND",
    "CAP_AUDIT_READ",
    "CAP_PERFMON",
    "CAP_BPF",
    "CAP_CHECKPOINT_RESTORE",
]


def decode_caps(hex_str):
    if not hex_str or hex_str == "N/A":
        return "N/A"
    val = int(hex_str, 16)
    if val == 0:
        return "None"
    caps = []
    for i in range(len(CAPABILITIES)):
        if (val & (1 << i)) != 0:
            caps.append(CAPABILITIES[i])
    if not caps:
        return hex_str
    return ", ".join(caps)


def parse_status(status_text):
    info = {}
    for line in status_text.split("\n"):
        if not line:
            continue
        parts = line.split(":\t")
        if len(parts) == 2:
            key = parts[0].strip()
            val = parts[1].strip()
            info[key] = val
    return info


def format_ns(ns_ls_output):
    ns_dict = {}
    for line in ns_ls_output.split("\n"):
        if " -> " in line:
            parts = line.split(" -> ")
            if len(parts) == 2:
                name = parts[0].split(" ")[-1]
                target = parts[1].strip()
                ns_dict[name] = target
    return ns_dict


def main(*args):
    pid = "self"
    if len(args) == 2:
        pid = args[1]
    print("==================================================")
    print(" Process Info of %s" % pid)
    print("==================================================")

    procfs_prefix = "/proc/" + pid
    cmdline = read_file(procfs_prefix + "/cmdline").strip("\x00").replace("\x00", " ")
    print("Cmdline:    %s" % (cmdline or "N/A"))

    status_text = read_file(procfs_prefix + "/status")
    status = parse_status(status_text)

    print("\n--- Identity & Privileges ---")
    print("Name:       %s" % status.get("Name", "N/A"))
    print("State:      %s" % status.get("State", "N/A"))
    print("PID:        %s" % status.get("Pid", "N/A"))
    print("PPID:       %s" % status.get("PPid", "N/A"))
    print("UIDs:       %s (Real, Effective, Saved, FS)" % status.get("Uid", "N/A"))
    print("GIDs:       %s (Real, Effective, Saved, FS)" % status.get("Gid", "N/A"))
    print("Groups:     %s" % status.get("Groups", "N/A"))

    print("\n--- Capabilities ---")
    print("Inheritable:\n  %s" % decode_caps(status.get("CapInh", "N/A")))
    print("Permitted:\n  %s" % decode_caps(status.get("CapPrm", "N/A")))
    print("Effective:\n  %s" % decode_caps(status.get("CapEff", "N/A")))
    print("Bounding:\n  %s" % decode_caps(status.get("CapBnd", "N/A")))
    print("Ambient:\n  %s" % decode_caps(status.get("CapAmb", "N/A")))
    print("NoNewPrivs: %s" % status.get("NoNewPrivs", "N/A"))

    print("\n--- Cgroups ---")
    cgroup_text = read_file(procfs_prefix + "/cgroup")
    for line in cgroup_text.split("\n"):
        if line:
            parts = line.split(":")
            if len(parts) >= 3:
                print(parts[2])

    print("\n--- Namespaces ---")
    ns_info = exec_cmd("ls", ["-l", procfs_prefix + "/ns"])
    namespaces = format_ns(ns_info)
    for k in sorted(namespaces.keys()):
        k_padded = k + ":"
        if len(k_padded) < 12:
            k_padded = k_padded + " " * (12 - len(k_padded))
        print("%s %s" % (k_padded, namespaces[k]))

    print("\n--- Environment ---")
    environ = read_file(procfs_prefix + "/environ")
    env_vars = [e for e in environ.split("\x00") if e]
    print("%d environment variables loaded." % len(env_vars))

    print("==================================================")
    return "OK"
