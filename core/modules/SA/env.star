# Starlark implementation of env/entry.c

def read_ansi_string(ptr):
    result = ""
    offset = 0
    # Process up to a reasonable max string length
    for i in range(4096):
        data = win_read_mem(ptr + offset, 1)
        b = data[0]
        if b == 0:
            break
        result += chr(b)
        offset += 1
    return result, offset + 1

def main(*args):
    print("Gathering Process Environment Variables:\n")
    
    # Get a pointer to the environment block
    res = win_call("kernel32.dll", "GetEnvironmentStrings")
    env_ptr = res["r1"]
    if env_ptr == 0:
        err_code = res.get("err_code", 0)
        err_msg = res.get("error", "")
        print("GetEnvironmentStrings failed. Error %d: %s" % (err_code, err_msg))
        return "Fail"
    
    current_ptr = env_ptr
    for i in range(1000):  # Safety limit for iterations
        # The block is terminated by an extra NULL byte (meaning a double NULL at the end of the block)
        data = win_read_mem(current_ptr, 1)
        if data[0] == 0:
            break
            
        val, length = read_ansi_string(current_ptr)
        print(val)
        current_ptr += length
        
    win_call("kernel32.dll", "FreeEnvironmentStringsA", env_ptr)
    return "OK"
