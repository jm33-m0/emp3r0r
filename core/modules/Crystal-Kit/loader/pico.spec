x64:
    load "bin/pico.x64.o"
        make object +disco
    
    # merge the hook functions
    load "bin/hooks.x64.o"
        merge

    # merge the call stack spoofing
    load "bin/spoof.x64.o"
        merge

    # merge the asm stub
    load "bin/draugr.x64.bin"
        linkfunc "draugr_stub"

    # merge mask
    load "bin/mask.x64.o"
        merge

    # generate and patch in a random key
    generate $KEY 128
    patch "xorkey" $KEY

    # merge cfg code
    load "bin/cfg.x64.o"
        merge
            
    # merge cleanup
    load "bin/cleanup.x64.o"
        merge

    # export setup_hooks and setup_memory
    exportfunc "setup_hooks"  "__tag_setup_hooks"
    exportfunc "setup_memory" "__tag_setup_memory"

    # hook functions in the DLL
    addhook "WININET$HttpSendRequestA"    "_HttpSendRequestA"
    addhook "WININET$InternetOpenA"       "_InternetOpenA"
    addhook "WININET$InternetConnectA"    "_InternetConnectA"
    addhook "WS2_32$WSAStartup"           "_WSAStartup"
    addhook "WS2_32$WSASocketA"           "_WSASocketA"
    addhook "KERNEL32$CloseHandle"        "_CloseHandle"
    addhook "KERNEL32$CreateFileMappingA" "_CreateFileMappingA"
    addhook "KERNEL32$CreateProcessA"     "_CreateProcessA"
    addhook "KERNEL32$CreateRemoteThread" "_CreateRemoteThread"
    addhook "KERNEL32$CreateThread"       "_CreateThread"
    addhook "KERNEL32$DuplicateHandle"    "_DuplicateHandle"
    addhook "KERNEL32$ExitThread"         "_ExitThread"
    addhook "KERNEL32$GetThreadContext"   "_GetThreadContext"
    addhook "KERNEL32$HeapAlloc"          "_HeapAlloc"
    addhook "KERNEL32$HeapReAlloc"        "_HeapReAlloc"
    addhook "KERNEL32$HeapFree"           "_HeapFree"
    addhook "KERNEL32$LoadLibraryA"       "_LoadLibraryA"
    addhook "KERNEL32$MapViewOfFile"      "_MapViewOfFile"
    addhook "KERNEL32$OpenProcess"        "_OpenProcess"
    addhook "KERNEL32$OpenThread"         "_OpenThread"
    addhook "KERNEL32$ReadProcessMemory"  "_ReadProcessMemory"
    addhook "KERNEL32$ResumeThread"       "_ResumeThread"
    addhook "KERNEL32$SetThreadContext"   "_SetThreadContext"
    addhook "KERNEL32$Sleep"              "_Sleep"
    addhook "KERNEL32$ExitProcess"        "_ExitProcess"
    addhook "KERNEL32$UnmapViewOfFile"    "_UnmapViewOfFile"
    addhook "KERNEL32$VirtualAlloc"       "_VirtualAlloc"
    addhook "KERNEL32$VirtualAllocEx"     "_VirtualAllocEx"
    addhook "KERNEL32$VirtualFree"        "_VirtualFree"
    addhook "KERNEL32$VirtualProtect"     "_VirtualProtect"
    addhook "KERNEL32$VirtualProtectEx"   "_VirtualProtectEx"
    addhook "KERNEL32$VirtualQuery"       "_VirtualQuery"
    addhook "KERNEL32$WriteProcessMemory" "_WriteProcessMemory"
    addhook "OLE32$CoCreateInstance"      "_CoCreateInstance"

    # hook functions in pico
    attach "KERNEL32$VirtualProtect" "_VirtualProtect"  # this is needed to hook VirtualProtect in mask.c

    mergelib "../libtcg.x64.zip"

    export
