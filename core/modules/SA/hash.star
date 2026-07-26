# Starlark implementation of md5 / sha1 / sha256 SA modules

def hash_file(algorithm, filepath):
    if not filepath:
        print("[-] Usage: hash <algo> <filepath>")
        return "Fail"

    algo = algorithm.lower()
    if algo not in ("md5", "sha1", "sha256", "sha512"):
        print("[-] Unsupported hash algorithm: %s" % algorithm)
        return "Fail"

    content = read_file(filepath)
    if content == None:
        print("[-] Failed to read file: %s" % filepath)
        return "Fail"

    digest = crypto_hash(algo, content)
    print("%s Hash for %s: %s" % (algo.upper(), filepath, digest))
    return "OK"

def main(*args):
    algo = args[0] if len(args) > 0 else "md5"
    filepath = args[1] if len(args) > 1 else ""
    return hash_file(algo, filepath)

main()
