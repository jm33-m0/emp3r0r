#include <windows.h>
#include "memory.h"
#include "spoof.h"
#include "cleanup.h"
#include "tcg.h"

MEMORY_LAYOUT g_memory;

DECLSPEC_IMPORT VOID WINAPI KERNEL32$ExitThread ( DWORD );

FARPROC WINAPI _GetProcAddress ( HMODULE hModule, LPCSTR lpProcName )
{
    /* lpProcName may be an ordinal */
    if ( ( ULONG_PTR ) lpProcName >> 16 == 0 )
    {
        /* just resolve normally */
        return GetProcAddress ( hModule, lpProcName );
    }

    FARPROC result = __resolve_hook ( ror13hash ( lpProcName ) );

    /*
     * result may still be NULL if 
     * it wasn't hooked in the spec
     */
    if ( result != NULL ) {
        return result;
    }
    
    return GetProcAddress ( hModule, lpProcName );
}

void setup_hooks ( IMPORTFUNCS * funcs )
{
    funcs->GetProcAddress = ( __typeof__ ( GetProcAddress ) * ) _GetProcAddress;
}

void setup_memory ( MEMORY_LAYOUT * layout )
{
    if ( layout != NULL ) {
        g_memory = * layout;
    }
}

/* 
 * throw these hooks in here because
 * sharing a global across multiple
 * modules is still a bit of a headache
 */

VOID WINAPI _ExitThread ( DWORD dwExitCode )
{
    /* free memory */
    cleanup_memory ( &g_memory );

    /* call the real exit thread */
    FUNCTION_CALL call = { 0 };

    call.ptr  = ( PVOID ) ( KERNEL32$ExitThread );
    call.argc = 1;
    
    call.args [ 0 ]  = spoof_arg ( dwExitCode );

    spoof_call ( &call );
}