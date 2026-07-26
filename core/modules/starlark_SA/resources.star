# Starlark implementation of resources/entry.c

def write_byte(addr, offset, val):
    win_call("msvcrt.dll", "memset", addr + offset, val & 0xFF, 1)

def write_uint32(addr, offset, val):
    write_byte(addr, offset, val & 0xFF)
    write_byte(addr, offset + 1, (val >> 8) & 0xFF)
    write_byte(addr, offset + 2, (val >> 16) & 0xFF)
    write_byte(addr, offset + 3, (val >> 24) & 0xFF)

def read_uint32(addr, offset):
    d = win_read_mem(addr + offset, 4)
    return d[0] | (d[1] << 8) | (d[2] << 16) | (d[3] << 24)

def read_uint64(addr, offset):
    l = read_uint32(addr, offset)
    h = read_uint32(addr, offset + 4)
    return (h << 32) | l

def get_resources():
    # MEMORYSTATUSEX size is 64 bytes
    mem_stat = win_alloc(64)
    write_uint32(mem_stat, 0, 64)

    res = win_call("kernel32.dll", "GlobalMemoryStatusEx", mem_stat)
    if res["r1"] == 0:
        win_free(mem_stat)
        print("[-] GlobalMemoryStatusEx failed")
        return "Fail"

    mem_load = read_uint32(mem_stat, 4)
    total_phys = read_uint64(mem_stat, 8) // (1024 * 1024)
    avail_phys = read_uint64(mem_stat, 16) // (1024 * 1024)
    total_page = read_uint64(mem_stat, 24) // (1024 * 1024)
    avail_page = read_uint64(mem_stat, 32) // (1024 * 1024)

    win_free(mem_stat)

    print("System Resources & Memory Status:")
    print("===========================================================================")
    print("Memory Load:           %d%%" % mem_load)
    print("Total Physical Memory: %d MB" % total_phys)
    print("Avail Physical Memory: %d MB" % avail_phys)
    print("Total Page File:       %d MB" % total_page)
    print("Avail Page File:       %d MB" % avail_page)

    return "OK"

def main(*args):
    return get_resources()

main()
