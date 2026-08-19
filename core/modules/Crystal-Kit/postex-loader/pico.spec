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
    addhook "KERNEL32$GetProcAddress" "_GetProcAddress"
    addhook "KERNEL32$LoadLibraryW"   "_LoadLibraryW"
    addhook "KERNEL32$ExitThread"     "_ExitThread"

    mergelib "../libtcg.x64.zip"

    export