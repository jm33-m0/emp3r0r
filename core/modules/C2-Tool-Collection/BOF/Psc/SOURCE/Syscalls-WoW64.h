#pragma once

// This function expects a syscall number in eax and will increment it once for every mayor version
// Note, this function will not work for all systemcalls. Only for most of them.
// Example:
// mov eax, 0x23                               ; Win 6.1 = 0x23, 6.2 = 0x24, 6.3 = 0x25, 10 = 0x26
// call ExecuteSimpleSystemCallBase

__asm__("ExecuteSimpleSystemCallBase:                     \n\
    pop ecx                                               \n\
    push ebp                                              \n\
    mov ebp, esp                                          \n\
    mov ecx, fs:[0x30]                                    \n\
ExecuteSimpleSystemCallBase_Check_X_X_XXXX:               \n\
    cmp word ptr [ecx+0x0A4], 10                          \n\
    je  ExecuteSimpleSystemCallBase_SystemCall_10_0_XXXX  \n\
    cmp word ptr [ecx+0x0A4], 6                           \n\
    jne  ExecuteSimpleSystemCallBase_Epilogue             \n\
ExecuteSimpleSystemCallBase_Check_6_X_XXXX:               \n\
    cmp word ptr [ecx+0x0A8], 3                           \n\
    je  ExecuteSimpleSystemCallBase_SystemCall_6_3_XXXX   \n\
    cmp word ptr [ecx+0x0A8], 2                           \n\
    je  ExecuteSimpleSystemCallBase_SystemCall_6_2_XXXX   \n\
    cmp word ptr [ecx+0x0A8], 1                           \n\
    jne  ExecuteSimpleSystemCallBase_Epilogue             \n\
    cmp word ptr [ecx+0x0AC], 7601                        \n\
    je  ExecuteSimpleSystemCallBase_SystemCall_6_1_7601   \n\
    jmp ExecuteSimpleSystemCallBase_Epilogue              \n\
ExecuteSimpleSystemCallBase_SystemCall_10_0_XXXX:         \n\
    inc eax                                               \n\
ExecuteSimpleSystemCallBase_SystemCall_6_3_XXXX:          \n\
    inc eax                                               \n\
ExecuteSimpleSystemCallBase_SystemCall_6_2_XXXX:          \n\
    inc eax                                               \n\
ExecuteSimpleSystemCallBase_SystemCall_6_1_7601:          \n\
ExecuteSimpleSystemCallBase_Argument_Count:               \n\
    mov ecx, 0x10                                         \n\
ExecuteSimpleSystemCallBase_Push_Argument:                \n\
    dec ecx                                               \n\
    push [ebp + 0x08 + ecx * 4]                           \n\
    jnz ExecuteSimpleSystemCallBase_Push_Argument         \n\
    lea ebx,[ExecuteSimpleSystemCallBase_Epilogue]        \n\
    push ebx                                              \n\
    call dword ptr fs:[0x0C0]                             \n\
    lea esp, [esp+4]                                      \n\
ExecuteSimpleSystemCallBase_Epilogue:                     \n\
    mov esp, ebp                                          \n\
    pop ebp                                               \n\
    ret                                                   \n\
    ");

__asm__("ZwQuerySystemInformation:                        \n\
    mov eax, 0x033                                        \n\
    call ExecuteSimpleSystemCallBase                      \n\
    ret                                                   \n\
    ");

__asm__("ZwQueryInformationProcess:                       \n\
    mov eax, 0x016                                        \n\
    call ExecuteSimpleSystemCallBase                      \n\
    ret                                                   \n\
    ");

__asm__("ZwOpenProcess:                                   \n\
    mov eax, 0x023                                        \n\
    call ExecuteSimpleSystemCallBase                      \n\
    ret                                                   \n\
    ");

__asm__("ZwAdjustPrivilegesToken:                         \n\
    mov eax, 0x03E                                        \n\
    call ExecuteSimpleSystemCallBase                      \n\
    ret                                                   \n\
    ");

__asm__("ZwQueryInformationToken:                         \n\
    mov eax, 0x01E                                        \n\
    call ExecuteSimpleSystemCallBase                      \n\
    ret                                                   \n\
    ");

__asm__("ZwAllocateVirtualMemory:                         \n\
    mov eax, 0x015                                        \n\
    call ExecuteSimpleSystemCallBase                      \n\
    ret                                                   \n\
    ");

__asm__("ZwFreeVirtualMemory:                             \n\
    mov eax, 0x01B                                        \n\
    call ExecuteSimpleSystemCallBase                      \n\
    ret                                                   \n\
    ");

__asm__("ZwReadVirtualMemory:                             \n\
    mov eax, 0x03C                                        \n\
    call ExecuteSimpleSystemCallBase                      \n\
    ret                                                   \n\
    ");

__asm__("ZwWriteVirtualMemory:                            \n\
    mov eax, 0x037                                        \n\
    call ExecuteSimpleSystemCallBase                      \n\
    ret                                                   \n\
    ");

__asm__("ZwCreateFile:                                    \n\
    mov eax, 0x052                                        \n\
    call ExecuteSimpleSystemCallBase                      \n\
    ret                                                   \n\
    ");

__asm__("ZwClose:                                         \n\
    mov eax, 0x00C                                        \n\
    call ExecuteSimpleSystemCallBase                      \n\
    ret                                                   \n\
    ");
