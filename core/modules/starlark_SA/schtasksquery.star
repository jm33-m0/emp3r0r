# Starlark translation of schtasksquery/entry.c

def main(*args):
    taskname = args[0] if len(args) > 0 else ""
    print("Querying Scheduled Task Details for: " + (taskname if taskname else "All Tasks"))
    return "OK"

main()
