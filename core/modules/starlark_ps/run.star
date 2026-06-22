# Starlark module for process listing on Linux agents

def main(*args):
    # Optional search filter from arguments/argv
    filter_query = ""
    if len(argv) > 0:
        filter_query = argv[0].lower()

    print("==================================================")
    print(" Linux Process Listing (via Starlark Engine) ")
    if filter_query:
        print(" Filter: '" + filter_query + "'")
    print("==================================================")
    print("%-8s %-8s %-20s %s" % ("PID", "PPID", "Name", "Cmdline"))
    print("-" * 80)

    processes = list_processes()
    count = 0
    matched = 0

    for proc in processes:
        count += 1
        pid = str(proc["pid"])
        ppid = str(proc["ppid"])
        name = proc["name"]
        cmdline = proc["cmdline"]

        # Apply filter if provided
        if filter_query:
            if filter_query not in name.lower() and filter_query not in cmdline.lower():
                continue

        matched += 1
        # Truncate cmdline if it's too long
        if len(cmdline) > 50:
            cmdline = cmdline[:47] + "..."

        # Left align formatting
        print("%-8s %-8s %-20s %s" % (pid, ppid, name, cmdline))

    print("-" * 80)
    print("Total Processes: %d, Matched: %d" % (count, matched))
    print("==================================================")
    return "OK"
