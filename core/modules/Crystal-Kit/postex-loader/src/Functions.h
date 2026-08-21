#pragma once

// clang-format off
#include "Common.h"
#include "Spoof.h"
#include <windows.h>

// clang-format on
PVOID GetExceptionDirectoryAddress(HMODULE hModule, DWORD *size);
DWORD GetStackFrameSize(HMODULE hModule, PVOID unwindInfoAddress,
                        DWORD *targetStackOffset);
DWORD GetStackFrameSizeIgnoringUwopSetFpreg(HMODULE moduleBase,
                                            PVOID unwindInfoAddress,
                                            DWORD *targetStackOffset);
DWORD GetStackFrameSizeWhereRbpIsPushedOnStack(HMODULE moduleBase,
                                               PVOID unwindInfoAddress,
                                               DWORD *targetStackOffset);

void FindProlog(HMODULE moduleBase, PRUNTIME_FUNCTION pRuntimeFunctionTable,
                DWORD rtLastIndex, PDWORD stackSize, PDWORD prtSaveIndex,
                PDWORD skip, PDWORD64 rtTargetOffset, PSPOOFER config);
DWORD FindPushRbp(HMODULE moduleBase, PRUNTIME_FUNCTION pRuntimeFunctionTable,
                  DWORD rtLastIndex, PDWORD stackSize, PDWORD prtSaveIndex,
                  PDWORD skip, PDWORD64 rtTargetOffset, PSPOOFER config);
void FindGadget(HMODULE moduleBase, PRUNTIME_FUNCTION pRuntimeFunctionTable,
                DWORD rtLastIndex, PDWORD stackSize, PDWORD prtSaveIndex,
                PDWORD skip, DWORD gadgetType, PSPOOFER config);
