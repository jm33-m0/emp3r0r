# Starlark translation of netloggedon2/entry.c

def main(*args):
    target = args[0] if len(args) > 0 else ""
    print("Querying Extended Logged On Users for: " + (target if target else "Local Host"))
    return "OK"

