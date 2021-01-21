#!/usr/bin/env python3

'''
generate shellcode from ./guardian.asm
using custom agent path
'''

# pylint: disable=invalid-name, broad-except

import os
import sys
import traceback

usage = f"{sys.argv[0]} <agent path>"

if len(sys.argv) != 2:
    print(usage)
    sys.exit(1)
agent_path = sys.argv[1]
agent_path = agent_path[::-1]

asm_source = open("./guardian.asm").read()
temp_asm_file = open("temp.asm", "w+")


asm_push_filename = "push rax\n"

filename_len = len(agent_path)

if filename_len <= 8:
    agent_path_hex = '0x'+agent_path.encode('utf-8').hex()
    asm_push_filename += f"mov rdi, {agent_path_hex}\npush rdi\n"
else:
    # push QWORD
    agent_path_hex = '0x'
    for char in agent_path:
        if len(agent_path_hex)/2 == 9:  # 8 bytes at a time
            asm_push_filename += f"mov rdi, {agent_path_hex}\npush rdi\n"
            agent_path_hex = '0x'
        agent_path_hex += char.encode('utf-8').hex()

    # pad string and make RSP point to its beginning
    if len(agent_path_hex)/2 < 9:
        padding = int(9 - len(agent_path_hex)/2)
        agent_path_hex = f"{agent_path_hex}{'00'*padding}"
        asm_push_filename += f"mov rdi, {agent_path_hex}\npush rdi\n"

        asm_push_filename += f"add rsp, {padding}\nmov rdi, rsp\n"


asm_source = asm_source.replace(";[push filename here]", asm_push_filename)
temp_asm_file.write(asm_source)
temp_asm_file.close()

# format code, assemble, convert to shellcode, write to shellcode.txt
try:
    os.system("nasm temp.asm -o shellcode.exe")
    os.system(
        r"xxd -i shellcode.exe | grep 0x | tr -d ',' | tr -d '[:space:]' | sed 's/0x/\\x/g' " +
        "| tee shellcode.txt")
except BaseException:
    print("Failed to generate guardian shellcode:\n" + traceback.format_exc())
    sys.exit(1)
