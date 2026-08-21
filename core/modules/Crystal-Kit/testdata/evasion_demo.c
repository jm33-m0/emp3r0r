/*
 * evasion_demo.c — benign demo DLL for the Crystal-Kit evasions loader
 * (loader/loader.spec, the upstream use-case-A loader).
 *
 * CRT-free and kernel32-only so it links/loads cleanly through Crystal
 * Palace's libtcg manual PE loader (no msvcrt dependency).
 *
 * DllMain deliberately calls APIs that the evasions loader hooks before it
 * runs the DLL:
 *
 *   - Sleep(1500)                     -> _Sleep hook: SilentMoonwalk call-stack
 *                                        spoofing + mask_memory() while
 * sleeping
 *   - HeapAlloc/HeapReAlloc/HeapFree  -> heap records are tracked and
 * XOR-masked
 *   - CreateThread/CloseHandle        -> stack-spoofed hooked calls
 *
 * It then writes a marker file to %TEMP%\ck_evasion_demo.txt so the PICO round
 * trip can be verified end-to-end.
 */
// clang-format off
#include <windows.h>

// clang-format on
static void write_marker(void) {
  char path[MAX_PATH];
  DWORD n = GetTempPathA(sizeof(path), path);
  if (n == 0 || n >= sizeof(path)) {
    lstrcpyA(path, "C:\\Windows\\Temp\\");
  }
  lstrcatA(path, "ck_evasion_demo.txt");

  HANDLE f = CreateFileA(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                         FILE_ATTRIBUTE_NORMAL, NULL);
  if (f == INVALID_HANDLE_VALUE) {
    return;
  }

  const char *msg = "Crystal-Kit evasions demo: DLL ran OK\r\n";
  DWORD written = 0;
  WriteFile(f, msg, lstrlenA(msg), &written, NULL);
  CloseHandle(f);
}

static DWORD WINAPI demo_thread(LPVOID param) {
  (void)param;
  return 0;
}

BOOL WINAPI DllMain(HINSTANCE hDll, DWORD fdwReason, LPVOID lpvReserved) {
  (void)hDll;
  (void)lpvReserved;

  if (fdwReason != DLL_PROCESS_ATTACH) {
    return TRUE;
  }

  /* _Sleep hook: stack spoof + memory mask (mask on >= 1s) */
  Sleep(1500);

  /* _HeapAlloc/_HeapReAlloc/_HeapFree hooks: track + mask heap records */
  HANDLE heap = GetProcessHeap();
  LPVOID p = HeapAlloc(heap, HEAP_ZERO_MEMORY, 4096);
  if (p != NULL) {
    p = HeapReAlloc(heap, HEAP_ZERO_MEMORY, p, 8192);
    if (p != NULL) {
      HeapFree(heap, 0, p);
    }
  }

  /* _CreateThread/_CloseHandle hooks: stack-spoofed calls */
  DWORD tid = 0;
  HANDLE t = CreateThread(NULL, 0, demo_thread, NULL, 0, &tid);
  if (t != NULL) {
    WaitForSingleObject(t, 1000);
    CloseHandle(t);
  }

  write_marker();
  return TRUE;
}
