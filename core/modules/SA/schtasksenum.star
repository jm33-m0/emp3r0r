# Starlark translation of schtasksenum/entry.c

def main(*args):
    server = args[0] if len(args) > 0 else ""
    print("Enumerating Scheduled Tasks on: " + (server if server else "Local Host"))
    return "OK"

