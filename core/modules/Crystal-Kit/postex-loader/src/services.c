#include <windows.h>

/* patch function pointers in */
__typeof__ ( GetModuleHandle ) * get_module_handle __attribute__ ( ( section ( ".text" ) ) );
__typeof__ ( GetProcAddress )  * get_proc_address  __attribute__ ( ( section ( ".text" ) ) );

/**
 * This function is used to locate functions in
 * modules that are loaded by default (K32 & NTDLL)
 */
FARPROC patch_resolve ( char * mod_name, char * func_name )
{
    HANDLE module = get_module_handle ( mod_name );
    return get_proc_address ( module, func_name );
}