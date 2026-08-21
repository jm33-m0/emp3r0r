// clang-format off
#include <windows.h>
#include "tcg.h"

// clang-format on
/**
 * This function is used to locate functions in
 * modules that are loaded by default (K32 & NTDLL)
 */
FARPROC patch_resolve(DWORD mod_hash, DWORD func_hash) {
  HANDLE module = findModuleByHash(mod_hash);
  return findFunctionByHash(module, func_hash);
}
