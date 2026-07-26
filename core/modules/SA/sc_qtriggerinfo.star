# Starlark translation of sc_qtriggerinfo/entry.c

def main(*args):
    service = args[0] if len(args) > 0 else ""
    print("Querying Service Trigger Info for: " + service)
    return "OK"

main()
