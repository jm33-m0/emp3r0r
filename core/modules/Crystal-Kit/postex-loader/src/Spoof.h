#pragma once

// clang-format off
#include <windows.h>

// clang-format on
#define spoof_arg(x) (ULONG_PTR)(x)

#define JMP_RBX 9215           /* 0x23ff little-endian : ff 23 (jmp [rbx]) */
#define ADD_RSP_0x38 952402760 /* 4883c438 reversed : 38c48348 */
#define RET 0xc3

typedef struct {
  PVOID KernelBaseAddress;
  PVOID KernelBaseAddressEnd;

  PVOID RtlUserThreadStartAddress;
  PVOID BaseThreadInitThunkAddress;

  PVOID FirstFrameFunctionPointer;
  PVOID SecondFrameFunctionPointer;
  PVOID JmpRbxGadget;
  PVOID AddRspXGadget;

  UINT64 FirstFrameSize;
  UINT64 FirstFrameRandomOffset;
  UINT64 SecondFrameSize;
  UINT64 SecondFrameRandomOffset;

  UINT64 JmpRbxGadgetFrameSize;
  UINT64 AddRspXGadgetFrameSize;

  UINT64 RtlUserThreadStartFrameSize;
  UINT64 BaseThreadInitThunkFrameSize;

  UINT64 StackOffsetWhereRbpIsPushed;

  PVOID JmpRbxGadgetRef;
  PVOID SpoofFunctionPointer;
  PVOID ReturnAddress;

  UINT64 Nargs;
  PVOID Arg01;
  PVOID Arg02;
  PVOID Arg03;
  PVOID Arg04;
  PVOID Arg05;
  PVOID Arg06;
  PVOID Arg07;
  PVOID Arg08;
} SPOOFER, *PSPOOFER;

/* Crystal-Kit hook ABI (not part of upstream SilentMoonwalk). */
typedef struct {
  PVOID ptr;
  DWORD ssn;
  int argc;
  ULONG_PTR args[10];
} FUNCTION_CALL;

ULONG_PTR spoof_call(FUNCTION_CALL *call);
