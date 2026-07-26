# Starlark translation of netuptime/entry.c

def main(*args):
    server = args[0] if len(args) > 0 else ""
    print("Querying Network Uptime for: " + (server if server else "Local Host"))
    return "OK"

