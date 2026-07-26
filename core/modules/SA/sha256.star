# Starlark translation of sha256/entry.c

def main(*args):
    filepath = args[0] if len(args) > 0 else ""
    if not filepath:
        print("[-] Usage: sha256 <filepath>")
        return "Fail"
    res = crypto_hash("sha256", filepath)
    print("SHA256 (%s) = %s" % (filepath, res))
    return "OK"

