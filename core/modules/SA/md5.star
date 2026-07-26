# Starlark translation of md5/entry.c

def main(*args):
    filepath = args[0] if len(args) > 0 else ""
    if not filepath:
        print("[-] Usage: md5 <filepath>")
        return "Fail"
    res = crypto_hash("md5", filepath)
    print("MD5 (%s) = %s" % (filepath, res))
    return "OK"

