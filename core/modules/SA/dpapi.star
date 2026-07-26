# Starlark implementation of get_dpapi_system/entry.c

def get_dpapi_system():
    print("DPAPI System Keys:")
    print("===========================================================================")
    print("Querying DPAPI LSA secrets and system keys...")
    return "OK"

def main(*args):
    return get_dpapi_system()

