#pragma once

// This function expects a syscall number in eax and will increment it once for every mayor version
// Note, this function will not work for all systemcalls. Only for most of them.
// Example:
// mov rax, 0x23                               ; Win 6.1 = 0x23, 6.2 = 0x24, 6.3 = 0x25, 10 = 0x26
// call ExecuteSimpleSystemCallBase

__asm__("ExecuteSimpleSystemCallBase:                     \n\
    mov r10, gs:[0x60]                                    \n\
ExecuteSimpleSystemCallBase_Check_X_X_XXXX:               \n\
    cmp word ptr [r10+0x118], 10                          \n\
    je  ExecuteSimpleSystemCallBase_SystemCall_10_0_XXXX  \n\
    cmp word ptr [r10+0x118], 6                           \n\
    jne ExecuteSimpleSystemCallBase_SystemCall_Unknown    \n\
ExecuteSimpleSystemCallBase_Check_6_X_XXXX:               \n\
    cmp word ptr [r10+0x11c], 3                           \n\
    je  ExecuteSimpleSystemCallBase_SystemCall_6_3_XXXX   \n\
    cmp word ptr [r10+0x11c], 2                           \n\
    je  ExecuteSimpleSystemCallBase_SystemCall_6_2_XXXX   \n\
    cmp word ptr [r10+0x11c], 1                           \n\
    jne ExecuteSimpleSystemCallBase_SystemCall_Unknown    \n\
ExecuteSimpleSystemCallBase_Check_6_1_XXXX:               \n\
    cmp word ptr [r10+0x120], 7601                        \n\
    je  ExecuteSimpleSystemCallBase_SystemCall_6_1_7601   \n\
    jmp ExecuteSimpleSystemCallBase_SystemCall_Unknown    \n\
ExecuteSimpleSystemCallBase_SystemCall_10_0_XXXX:         \n\
    inc eax                                               \n\
ExecuteSimpleSystemCallBase_SystemCall_6_3_XXXX:          \n\
    inc eax                                               \n\
ExecuteSimpleSystemCallBase_SystemCall_6_2_XXXX:          \n\
    inc eax                                               \n\
ExecuteSimpleSystemCallBase_SystemCall_6_1_7601:          \n\
ExecuteSimpleSystemCallBase_Epilogue:                     \n\
    pop r10                                               \n\
    mov r10, rcx                                          \n\
    syscall                                               \n\
ExecuteSimpleSystemCallBase_Finished:                     \n\
ExecuteSimpleSystemCallBase_SystemCall_Unknown:           \n\
    ret                                                   \n\
    ");

__asm__("ZwClose:                                         \n\
    mov rax, 0x00C                                        \n\
    call ExecuteSimpleSystemCallBase                      \n\
    ret                                                   \n\
    ");

__asm__("ZwOpenKey:                                       \n\
    mov rax, 0x00F                                        \n\
    call ExecuteSimpleSystemCallBase                      \n\
    ret                                                   \n\
    ");

__asm__("ZwQueryValueKey:                                 \n\
    mov rax, 0x014                                        \n\
    call ExecuteSimpleSystemCallBase                      \n\
    ret                                                   \n\
    ");

__asm__("GetTEBAsm64:                                     \n\
    push rbx                                              \n\
    xor rbx, rbx                                          \n\
    xor rax, rax                                          \n\
    mov rbx, qword ptr gs:[0x30]                          \n\
    mov rax, rbx                                          \n\
    pop rbx                                               \n\
    ret                                                   \n\
    ");
