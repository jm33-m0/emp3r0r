/* Test DLL that writes the lpReserved argument it receives in DllMain to the
 * file named by the CK_ARGS_OUT environment variable. Used by the crystal_kit
 * module test to verify end-to-end runtime argument delivery. */
#include <windows.h>

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    (void)hinstDLL;

    if (fdwReason != DLL_PROCESS_ATTACH) {
        return TRUE;
    }

    char outPath[MAX_PATH];
    DWORD pathLen = GetEnvironmentVariableA("CK_ARGS_OUT", outPath, MAX_PATH);
    if (pathLen == 0 || pathLen >= MAX_PATH) {
        return TRUE;
    }

    HANDLE file = CreateFileA(outPath, GENERIC_WRITE, 0, NULL,
                              CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE) {
        return TRUE;
    }

    LPCSTR raw = (LPCSTR)lpvReserved;
    if (raw != NULL) {
        /* The PICO runner prefixes a pipe handle as "<hex>|" when runtime
         * args are used. Baked args have no pipe prefix. */
        LPCSTR args = raw;
        const char *p = raw;
        while (*p && *p != '|') p++;
        if (*p == '|') args = p + 1;

        DWORD len = lstrlenA(args);
        DWORD written = 0;
        WriteFile(file, args, len, &written, NULL);
    }

    CloseHandle(file);
    return TRUE;
}
