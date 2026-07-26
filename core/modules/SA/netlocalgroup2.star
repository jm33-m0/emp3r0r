# Starlark translation of netlocalgroup2/entry.c

def main(*args):
    server = args[0] if len(args) > 0 else ""
    group = args[1] if len(args) > 1 else ""
    print("Querying NetLocalGroup2 for group '%s' on '%s'" % (group, server if server else "Local Host"))
    return "OK"

