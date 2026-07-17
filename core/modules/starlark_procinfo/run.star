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
                # e.g., parts[0] = "lrwxrwxrwx 1 user user 0 Jul 17 09:28 cgroup"
                # parts[1] = "cgroup:[4026531835]"
                name = parts[0].split(" ")[-1]
                target = parts[1].strip()
                ns_dict[name] = target
    return ns_dict


def main(*args):
    print("==================================================")
    print(" Current Process Info ")
    print("==================================================")

    status_text = read_file("/proc/self/status")
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
    print("Inheritable:%s" % status.get("CapInh", "N/A"))
    print("Permitted:  %s" % status.get("CapPrm", "N/A"))
    print("Effective:  %s" % status.get("CapEff", "N/A"))
    print("Bounding:   %s" % status.get("CapBnd", "N/A"))
    print("Ambient:    %s" % status.get("CapAmb", "N/A"))
    print("NoNewPrivs: %s" % status.get("NoNewPrivs", "N/A"))

    print("\n--- Cgroups ---")
    cgroup_text = read_file("/proc/self/cgroup")
    for line in cgroup_text.split("\n"):
        if line:
            # format: hierarchy_ID:controller_list:cgroup_path
            parts = line.split(":")
            if len(parts) >= 3:
                cgroup_path = parts[2]
                print(cgroup_path)

    print("\n--- Namespaces ---")
    ns_info = exec_cmd("ls", ["-l", "/proc/self/ns"])
    namespaces = format_ns(ns_info)
    for k in sorted(namespaces.keys()):
        print("%-12s %s" % (k + ":", namespaces[k]))

    print("==================================================")
    return "OK"
