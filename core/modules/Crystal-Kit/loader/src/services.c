#include <windows.h>
#include "tcg.h"

/* for the local loader */
__typeof__ ( GetModuleHandle ) * get_module_handle __attribute__ ( ( section ( ".text" ) ) );
__typeof__ ( GetProcAddress )  * get_proc_address  __attribute__ ( ( section ( ".text" ) ) );

/**
 * This function is used to locate functions in
 * modules that are loaded by default (K32 & NTDLL)
 */
FARPROC resolve ( DWORD mod_hash, DWORD func_hash )
{
    HANDLE module = findModuleByHash ( mod_hash );
    return findFunctionByHash ( module, func_hash );
}

/**
 * This function is used to locate functions in
 * modules that are loaded by default (K32 & NTDLL)
 */
FARPROC patch_resolve ( char * mod_name, char * func_name )
{
    HANDLE module = get_module_handle ( mod_name );
    return get_proc_address ( module, func_name );
}