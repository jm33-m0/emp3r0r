# Starlark translation of sha1/entry.c

def main(*args):
    filepath = args[0] if len(args) > 0 else ""
    if not filepath:
        print("[-] Usage: sha1 <filepath>")
        return "Fail"
    res = crypto_hash("sha1", filepath)
    print("SHA1 (%s) = %s" % (filepath, res))
    return "OK"

