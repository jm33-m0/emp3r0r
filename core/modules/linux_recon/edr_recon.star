# linux_edr_recon - local Linux EDR / kernel-telemetry audit.
#
# Ported to Starlark from Furtex's edrs/edr_recon.c.
# Upstream project: https://github.com/MatheuZSecurity/Furtex (MIT License,
# Copyright (c) 2026 MatheuZ). See README.md in this directory for attribution.
#
# The upstream BPF program/link/map enumeration is now driven through the
# bundled libbpf loader (`ebpf_*` builtins). The available_filter_functions scan
# is still opt-in because it can read tens of megabytes on a full kernel; run
# `--section avail` explicitly if you accept that cost.

# EDR vendor fingerprints. Keys mirror the upstream profile struct:
#   procs   - /proc/<pid>/comm substrings
#   modules - /proc/modules names (substring) and available_filter_functions
#             module names (exact) 
#   files   - filesystem paths whose existence scores the vendor
#   devs    - /dev/<name> device nodes
#   bpf     - substring patterns used against kprobe/trace lines
EDR_PROFILES = [
    {
        "vendor": "CrowdStrike Falcon",
        "procs": ["falcon-sensor", "falcond", "cs-agent"],
        "modules": ["falcon_lsm_sensor", "falcon_nf_netcontain", "falcon_kal"],
        "files": ["/opt/CrowdStrike/falcond", "/opt/CrowdStrike/falcon-sensor",
                  "/var/run/falcon-agent.socket", "/opt/CrowdStrike/"],
        "devs": ["falcon-query0", "csagent"],
        "bpf": ["falcon", "crowdstrike", "cs_"],
    },
    {
        "vendor": "Palo Alto Cortex XDR (Traps)",
        "procs": ["traps_pmd", "traps", "cytool", "cyserver"],
        "modules": ["traps"],
        "files": ["/opt/traps/bin/cytool", "/opt/traps/bin/traps_pmd",
                  "/opt/traps/running_mode", "/opt/traps/"],
        "devs": ["traps"],
        "bpf": ["traps", "cortex"],
    },
    {
        "vendor": "Trend Micro (DS Agent / Apex One)",
        "procs": ["ds_agent", "dsa_query", "cgtool", "ds_am"],
        "modules": ["tmhook", "bmhook", "dsa_filter", "dsa_filter_hook"],
        "files": ["/opt/ds_agent/ds_agent", "/opt/ds_agent/",
                  "/opt/TrendMicro/SProtectLinux/"],
        "devs": [],
        "bpf": ["tmhook", "bmhook", "trendmicro"],
    },
    {
        "vendor": "SentinelOne",
        "procs": ["sentinelctl", "sentinel-agent", "s1agent", "sentineld"],
        "modules": ["s1_sensor", "sentinel"],
        "files": ["/opt/sentinelone/bin/sentinelctl", "/opt/sentinelone/bin/sentineld",
                  "/opt/sentinelone/"],
        "devs": ["s1_sensor"],
        "bpf": ["s1_", "sentinel"],
    },
    {
        "vendor": "VMware Carbon Black",
        "procs": ["cbsensor", "cbdaemon", "cbagentd", "cbosxsensor"],
        "modules": ["cbr_sensord", "carbonblack"],
        "files": ["/usr/share/cb/cbdaemon", "/var/lib/cb/", "/opt/carbonblack/"],
        "devs": [],
        "bpf": ["carbonblack", "cbr_"],
    },
    {
        "vendor": "Microsoft Defender (MDATP)",
        "procs": ["mdatp", "wdavdaemon", "mdatp_audisp_plugin"],
        "modules": [],
        "files": ["/opt/microsoft/mdatp/sbin/wdavdaemon",
                  "/var/opt/microsoft/mdatp/", "/opt/microsoft/mdatp/"],
        "devs": [],
        "bpf": ["mdatp", "defender", "microsoft"],
    },
    {
        "vendor": "Sophos",
        "procs": ["sophoslinuxsensor", "sophos-spl", "ssm-service"],
        "modules": [],
        "files": ["/opt/sophos-spl/bin/", "/opt/SophosLinux/", "/opt/sophos-spl/"],
        "devs": [],
        "bpf": ["sophos"],
    },
    {
        "vendor": "Elastic Endpoint",
        "procs": ["elastic-endpoint", "elastic-agent", "fleet-server"],
        "modules": [],
        "files": ["/opt/Elastic/Endpoint/elastic-endpoint",
                  "/opt/Elastic/Agent/elastic-agent", "/opt/Elastic/"],
        "devs": [],
        "bpf": ["elastic", "endgame"],
    },
    {
        "vendor": "Kaspersky (KESL)",
        "procs": ["kesl", "kavstart", "klnagent", "kav"],
        "modules": ["gsch", "klhk", "klrg", "klif"],
        "files": ["/opt/kaspersky/kesl/bin/kesl", "/var/opt/kaspersky/",
                  "/opt/kaspersky/"],
        "devs": ["klbg", "kl_vtd", "kl_protect"],
        "bpf": ["kaspersky", "kesl"],
    },
    {
        "vendor": "Wazuh / OSSEC",
        "procs": ["wazuh-agent", "wazuh-modulesd", "wazuh-syscheckd",
                  "wazuh-logcollectord", "ossec-agentd"],
        "modules": [],
        "files": ["/var/ossec/bin/wazuh-agent", "/etc/wazuh-agent/", "/var/ossec/"],
        "devs": [],
        "bpf": ["wazuh", "ossec"],
    },
    {
        "vendor": "Falco",
        "procs": ["falco", "falco-bpf"],
        "modules": ["scap", "falco_kmod"],
        "files": ["/usr/bin/falco", "/etc/falco/falco.yaml", "/etc/falco/"],
        "devs": ["scap0", "falco"],
        "bpf": ["falco", "scap", "sysdig"],
    },
    {
        "vendor": "Tetragon / Cilium",
        "procs": ["tetragon", "tetra", "cilium-agent"],
        "modules": [],
        "files": ["/usr/local/bin/tetragon", "/etc/tetragon/", "/usr/local/bin/tetra"],
        "devs": [],
        "bpf": ["tg_", "tetragon", "cilium"],
    },
]

# Sections included by the default "all". "avail" is intentionally opt-in.
SECTIONS_DEFAULT = ["procs", "arts", "mods", "kprobes", "ftrace", "lsm", "perf", "bpf"]

KPROBE_EVENTS = [
    "/sys/kernel/tracing/kprobe_events",
    "/sys/kernel/debug/tracing/kprobe_events",
]
FTRACE_FUNCS = [
    "/sys/kernel/tracing/enabled_functions",
    "/sys/kernel/debug/tracing/enabled_functions",
]
AVAIL_FUNCS = [
    "/sys/kernel/tracing/available_filter_functions",
    "/sys/kernel/debug/tracing/available_filter_functions",
]


def _is_pid(name):
    if not name:
        return False
    c = name[0]
    return c >= "0" and c <= "9"


def _add_score(scores, vendor, delta):
    scores[vendor] = scores.get(vendor, 0) + delta


def _vendor_for(text, field):
    # Substring match, case-insensitive (process/artifact/module names).
    low = str_lower(text)
    for prof in EDR_PROFILES:
        for pat in prof.get(field, []):
            if pat and str_contains(low, str_lower(pat)):
                return prof["vendor"]
    return None


def _vendor_exact(text, field):
    # Exact match, case-insensitive (available_filter_functions module names).
    low = str_lower(text)
    for prof in EDR_PROFILES:
        for pat in prof.get(field, []):
            if low == str_lower(pat):
                return prof["vendor"]
    return None


def _read_first(paths):
    # Starlark has no try/except; read_file(default="") makes these best-effort.
    for p in paths:
        data = read_file(p, default="")
        if data:
            return data, p
    return "", ""


def recon_processes(scores):
    print("=== Processes ===")
    found = 0
    for pid in list_dir("/proc"):
        if not _is_pid(pid):
            continue
        comm = read_file("/proc/%s/comm" % pid, default="").strip()
        if not comm:
            continue
        vendor = _vendor_for(comm, "procs")
        if vendor:
            print(sprintf("  [!] pid=%-6s comm=%-22s vendor=%s", pid, comm, vendor))
            _add_score(scores, vendor, 10)
            found += 1
    if found == 0:
        print("  [*] no known EDR processes found")
    return found


def recon_artifacts(scores):
    print("=== Filesystem Artifacts ===")
    found = 0
    for prof in EDR_PROFILES:
        for path in prof.get("files", []):
            if exists(path):
                print(sprintf("  [!] %-44s vendor=%s", path, prof["vendor"]))
                _add_score(scores, prof["vendor"], 5)
                found += 1
        for dev in prof.get("devs", []):
            path = "/dev/%s" % dev
            if exists(path):
                print(sprintf("  [!] %-44s vendor=%s", path, prof["vendor"]))
                _add_score(scores, prof["vendor"], 8)
                found += 1
    if found == 0:
        print("  [*] no known EDR artifacts found")
    return found


def recon_modules(scores):
    print("=== Kernel Modules ===")
    content = read_file("/proc/modules", default="")
    if not content:
        print("  [!] /proc/modules not readable")
        return 0
    found = 0
    for line in content.splitlines():
        parts = line.split()
        if len(parts) < 3:
            continue
        name = parts[0]
        refcnt = parts[2]
        state = parts[4] if len(parts) > 4 else "?"
        vendor = _vendor_for(name, "modules")
        if vendor:
            print(sprintf("  [!] %-30s refcnt=%-4s state=%-12s vendor=%s", name, refcnt, state, vendor))
            _add_score(scores, vendor, 10)
            found += 1
    if found == 0:
        print("  [*] no known EDR modules loaded")
    return found


def recon_kprobes(scores):
    print("=== Active kprobes (tracefs) ===")
    content, path = _read_first(KPROBE_EVENTS)
    if not content:
        print("  [!] tracefs not accessible (need root and tracefs mounted)")
        return 0
    print("  [source: %s]" % path)
    total = 0
    edr = 0
    for line in content.splitlines():
        if not line:
            continue
        vendor = _vendor_for(line, "modules")
        if not vendor:
            vendor = _vendor_for(line, "bpf")
        if vendor:
            print("  [!EDR!] %s" % line)
            _add_score(scores, vendor, 2)
            edr += 1
        else:
            print("  %s" % line)
        total += 1
    print("  total=%d edr_pattern=%d" % (total, edr))
    return total


def recon_ftrace(scores):
    print("=== ftrace function hooks (enabled_functions) ===")
    content, path = _read_first(FTRACE_FUNCS)
    if not content:
        print("  [!] enabled_functions not accessible")
        print("  [*] LKM ftrace hooks appear here and cannot be removed via tracefs")
        return 0
    print("  [source: %s]" % path)
    total = 0
    for line in content.splitlines():
        if not line:
            continue
        vendor = _vendor_for(line, "modules")
        if vendor:
            print("  [!EDR!] %s" % line)
            _add_score(scores, vendor, 3)
        else:
            print("  %s" % line)
        total += 1
    print("  total=%d" % total)
    return total


def recon_lsm():
    print("=== Active LSM Stack ===")
    stack = read_file("/sys/kernel/security/lsm", default="").strip()
    if stack:
        print("  lsm stack: %s" % stack)
    else:
        print("  [!] /sys/kernel/security/lsm not readable")
    print("  [*] BPF LSM programs are not visible from userspace without bpf(2)")


def recon_perf(scores):
    print("=== Perf-attached BPF programs (no BPF_LINK) ===")
    total = 0
    for pid in list_dir("/proc"):
        if not _is_pid(pid):
            continue
        fdinfo = "/proc/%s/fdinfo" % pid
        for fd in list_dir(fdinfo):
            data = read_file("%s/%s" % (fdinfo, fd), default="")
            if not data:
                continue
            for line in data.splitlines():
                if str_startswith(line, "prog_id:"):
                    print(sprintf("  pid=%-6s fd=%-6s %s", pid, fd, line.strip()))
                    total += 1
                    break
    if total == 0:
        print("  [*] none found")
    else:
        print("  [!] %d perf-attached BPF programs (not removable via BPF_LINK)" % total)
    return total


def recon_bpf(scores):
    print("=== BPF programs / links / maps ===")
    progs = ebpf_progs()
    links = ebpf_links()
    maps = ebpf_maps()
    err = progs["error"] or links["error"] or maps["error"]
    if err:
        print("  [!] libbpf unavailable: %s" % err)
        return 0

    names = {}
    total = 0
    for p in progs["progs"]:
        names[p["id"]] = p["name"]
        vendor = _vendor_for(p["name"], "bpf")
        if vendor:
            print(sprintf("  [!] prog id=%-5d type=%-3d name=%-24s vendor=%s",
                          p["id"], p["type"], p["name"], vendor))
            _add_score(scores, vendor, 3)
        total += 1
    for l in links["links"]:
        pname = names.get(l["prog_id"], "")
        vendor = _vendor_for(pname, "bpf")
        if vendor:
            print(sprintf("  [!] link id=%-5d prog_id=%-5d prog=%-24s vendor=%s",
                          l["id"], l["prog_id"], pname, vendor))
            _add_score(scores, vendor, 3)
        total += 1
    for m in maps["maps"]:
        vendor = _vendor_for(m["name"], "bpf")
        if vendor:
            print(sprintf("  [!] map  id=%-5d name=%-24s key=%-4d value=%-4d max=%-6d vendor=%s",
                          m["id"], m["name"], m["key_size"], m["value_size"], m["max_entries"], vendor))
            _add_score(scores, vendor, 2)
        total += 1
    if total == 0:
        print("  [*] no BPF objects visible (need CAP_BPF/CAP_SYS_ADMIN)")
    return total


def recon_avail(scores):
    print("=== Available filter functions (EDR module symbols) ===")
    content, path = _read_first(AVAIL_FUNCS)
    if not content:
        print("  [!] available_filter_functions not accessible (need root)")
        return 0
    print("  [source: %s]" % path)
    hits = {}
    total = 0
    for line in content.splitlines():
        ob = str_index(line, "[")
        if ob < 0:
            continue
        rel = str_index(line[ob:], "]")
        if rel <= 1:
            continue
        modname = line[ob + 1:ob + rel]
        vendor = _vendor_exact(modname, "modules")
        if not vendor:
            continue
        n = hits.get(vendor, 0)
        if n < 5:
            print(sprintf("  [!] %-56s [%s] vendor=%s", line.strip(), modname, vendor))
        elif n == 5:
            print("  [!] ... more %s symbols from [%s]" % (vendor, modname))
        hits[vendor] = n + 1
        total += 1
        _add_score(scores, vendor, 1)
    if total == 0:
        print("  [*] no known EDR module symbols found")
    return total


def print_summary(scores):
    print("")
    print("=== Detection Summary ===")
    any_found = False
    for prof in EDR_PROFILES:
        score = scores.get(prof["vendor"], 0)
        if score == 0:
            continue
        level = "HIGH" if score >= 20 else ("MEDIUM" if score >= 10 else "LOW")
        print(sprintf("  [!] %-40s score=%-4d %s", prof["vendor"], score, level))
        any_found = True
    if not any_found:
        print("  [*] no EDR indicators found")


def main(*args):
    section = "all"
    if args and args[0]:
        section = str_lower(args[0].strip())

    if section in ("", "all"):
        wanted = list(SECTIONS_DEFAULT)
    else:
        wanted = section.split(",")

    print("[*] Linux EDR recon - %d vendor profiles" % len(EDR_PROFILES))
    scores = {}
    if "procs" in wanted:
        recon_processes(scores)
    if "arts" in wanted:
        recon_artifacts(scores)
    if "mods" in wanted:
        recon_modules(scores)
    if "kprobes" in wanted:
        recon_kprobes(scores)
    if "ftrace" in wanted:
        recon_ftrace(scores)
    if "lsm" in wanted:
        recon_lsm()
    if "perf" in wanted:
        recon_perf(scores)
    if "bpf" in wanted:
        recon_bpf(scores)
    if "avail" in wanted:
        recon_avail(scores)
    print_summary(scores)
    return "OK"
