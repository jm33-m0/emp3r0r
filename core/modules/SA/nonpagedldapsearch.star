# Starlark translation of nonpagedldapsearch/entry.c

def main(*args):
    query = args[0] if len(args) > 0 else "(objectClass=*)"
    print("Performing Non-Paged LDAP Search: " + query)
    return "OK"

