#pragma once

#include <windows.h>

#define SEED 123456

typedef UCHAR UBYTE;

typedef union _UNWIND_CODE {
  struct {
    UBYTE CodeOffset;
    UBYTE UnwindOp : 4;
    UBYTE OpInfo : 4;
  };
  USHORT FrameOffset;
} UNWIND_CODE, *PUNWIND_CODE;

typedef struct _UNWIND_INFO {
  UBYTE Version : 3;
  UBYTE Flags : 5;
  UBYTE SizeOfProlog;
  UBYTE CountOfCodes;
  UBYTE FrameRegister : 4;
  UBYTE FrameOffset : 4;
  UNWIND_CODE UnwindCode[1];
} UNWIND_INFO, *PUNWIND_INFO;

typedef enum _UNWIND_OP_CODES {
  UWOP_PUSH_NONVOL = 0,
  UWOP_ALLOC_LARGE,
  UWOP_ALLOC_SMALL,
  UWOP_SET_FPREG,
  UWOP_SAVE_NONVOL,
  UWOP_SAVE_NONVOL_BIG,
  UWOP_EPILOG,
  UWOP_SPARE_CODE,
  UWOP_SAVE_XMM128,
  UWOP_SAVE_XMM128BIG,
  UWOP_PUSH_MACHFRAME
} UNWIND_OP_CODES;

typedef enum _REGISTERS {
  RAX = 0,
  RCX,
  RDX,
  RBX,
  RSP,
  RBP,
  RSI,
  RDI,
  R8,
  R9,
  R10,
  R11,
  R12,
  R13,
  R14,
  R15
} REGISTERS;

void *custom_memset(void *dest, int val, size_t len);
