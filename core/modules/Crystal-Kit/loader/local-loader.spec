x64:
    load "bin/loader.x64.o"
        make pic +gofirst +optimize +disco
    
    # merge services
    load "bin/services.x64.o"
        merge

    dfr "patch_resolve" "strings"
    mergelib "../libtcg.x64.zip"

    # patch smart pointers in
    patch "get_module_handle" $GMH
    patch "get_proc_address"  $GPA

    # merge hooks into the loader
    load "bin/hooks.x64.o"
        merge

    # merge call stack spoofing into the loader
    load "bin/SilentMoonwalk.x64.o"
        merge

    # load the stack spoofing assembly
    load "bin/DesyncSpoofer.x64.bin"
        linkfunc "silentmoonwalk_spoof_call"

    # hook functions that the loader uses
    attach "KERNEL32$LoadLibraryA"    "_LoadLibraryA"
    attach "KERNEL32$VirtualAlloc"    "_VirtualAlloc"
    attach "KERNEL32$VirtualProtect"  "_VirtualProtect"
    attach "KERNEL32$VirtualFree"     "_VirtualFree"

    # mask & link the dll
    # Crystal Palace resolves a relocation against a linked section by its
    # symbol name. Clang emits relocations against the C marker symbols
    # (_DLL_/_MASK_/_PICO_); GCC instead emits the section symbols
    # (dll/mask/pico). This project builds with Zig's clang, so link under
    # the marker names.
    generate $MASK 128
    
    push $DLL
        xor $MASK
        preplen
        link "_DLL_"

    push $MASK
        preplen
        link "_MASK_"

    # now get the tradecraft as a PICO
    run "pico.spec"
        link "_PICO_"

    export