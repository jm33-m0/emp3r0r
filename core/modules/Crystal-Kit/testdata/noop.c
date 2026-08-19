/* Benign no-op DLL used to build the PICO test fixture for the crystal_kit
 * module test suite. DllMain simply returns TRUE so the PICO round trip can be
 * exercised without side effects or user interaction. */
#include <windows.h>

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    (void)hinstDLL;
    (void)fdwReason;
    (void)lpvReserved;
    return TRUE;
}
