[BITS 64]

    draugr_stub:
        pop rax                  ; Real return address in rax

        mov r10, rdi             ; Store OG rdi in r10
        mov r11, rsi             ; Store OG rsi in r11

        mov rdi, [ rsp + 32 ]    ; Storing struct in rdi
        mov rsi, [ rsp + 40 ]    ; Storing function to call

        ; ---------------------------------------------------------------------
        ; Storing our original registers
        ; ---------------------------------------------------------------------

        mov [ rdi + 24 ], r10     ; Storing OG rdi into param
        mov [ rdi + 88 ], r11     ; Storing OG rsi into param
        mov [ rdi + 96 ], r12     ; Storing OG r12 into param
        mov [ rdi + 104 ], r13    ; Storing OG r13 into param
        mov [ rdi + 112 ], r14    ; Storing OG r14 into param
        mov [ rdi + 120 ], r15    ; Storing OG r15 into param

        mov r12, rax              ; OG code used r12 for ret addr

        ; ---------------------------------------------------------------------
        ; Prepping to move stack args
        ; ---------------------------------------------------------------------

        xor r11, r11               ; r11 will hold the # of args that have been "pushed"
        mov r13, [ rsp + 0x30 ]    ; r13 will hold the # of args total that will be pushed

        mov r14, 0x200             ; r14 will hold the offset we need to push stuff
        add r14, 8
        add r14, [ rdi + 56 ]      ; stack size of RUTS
        add r14, [ rdi + 48 ]      ; stack size of BTIT
        add r14, [ rdi + 32 ]      ; stack size of our gadget frame
        sub r14, 0x20              ; first stack arg is located at +0x28 from rsp, so we sub 0x20 from the offset. Loop will sub 0x8 each time

        mov r10, rsp            
        add r10, 0x30              ; offset of stack arg added to rsp

        looping:
            xor r15, r15      ; r15 will hold the offset + rsp base
            cmp r11d, r13d    ; comparing # of stack args added vs # of stack args we need to add
            je finish
        
            ; ---------------------------------------------------------------------
            ; Getting location to move the stack arg to
            ; ---------------------------------------------------------------------
            
            sub r14, 8      ; 1 arg means r11 is 0, r14 already 0x28 offset.
            mov r15, rsp    ; get current stack base
            sub r15, r14    ; subtract offset
            
            ; ---------------------------------------------------------------------
            ; Procuring the stack arg
            ; ---------------------------------------------------------------------
            
            add r10, 8

            push qword [ r10 ]
            pop qword [ r15 ]   

            ; ---------------------------------------------------------------------
            ; Increment the counter and loop back in case we need more args
            ; ---------------------------------------------------------------------
            add r11, 1
            jmp looping
            
        finish:

        ; ----------------------------------------------------------------------
        ; Creating a big 320 byte working space
        ; ----------------------------------------------------------------------

        sub rsp, 0x200

        ; ----------------------------------------------------------------------
        ; Pushing a 0 to cut off the return addresses after RtlUserThreadStart.
        ; Need to figure out why this cuts off the call stack
        ; ----------------------------------------------------------------------

        push 0

        ; ----------------------------------------------------------------------
        ; RtlUserThreadStart + 0x14  frame
        ; ----------------------------------------------------------------------
        
        sub rsp, [ rdi + 56 ]
        mov r11, [ rdi + 64 ]
        mov [ rsp ], r11
                
        ; ----------------------------------------------------------------------
        ; BaseThreadInitThunk + 0x21  frame
        ; ----------------------------------------------------------------------

        sub rsp, [ rdi + 32 ]
        mov r11, [ rdi + 40 ]
        mov [ rsp ], r11

        ; ----------------------------------------------------------------------
        ; Gadget frame
        ; ----------------------------------------------------------------------
        
        sub rsp, [ rdi + 48 ]
        mov r11, [ rdi + 80 ]
        mov [ rsp ], r11

        ; ----------------------------------------------------------------------
        ; Adjusting the param struct for the fixup
        ; ----------------------------------------------------------------------

        mov r11, rsi              ; Copying function to call into r11

        mov [ rdi + 8 ], r12      ; Real return address is now moved into the "OG_retaddr" member
        mov [ rdi + 16 ], rbx     ; original rbx is stored into "rbx" member
        lea rbx, [ rel fixup ]    ; Fixup address is moved into rbx
        mov [ rdi ], rbx          ; Fixup member now holds the address of Fixup
        mov rbx, rdi              ; Address of param struct (Fixup) is moved into rbx

        ; ----------------------------------------------------------------------
        ; Syscall stuff. Shouldn't affect performance even if a syscall isnt made
        ; ----------------------------------------------------------------------
        mov r10, rcx
        mov rax, [ rdi + 72 ]
        
        jmp r11

        fixup:
            mov rcx, rbx
            add rsp, 0x200           ; Big frame thing
            add rsp, [ rbx + 48 ]    ; Stack size
            add rsp, [ rbx + 32 ]    ; Stack size
            add rsp, [ rbx + 56 ]    ; Stack size

            mov rbx, [ rcx + 16 ]     ; Restoring OG RBX
            mov rdi, [ rcx + 24 ]     ; ReStoring OG rdi
            mov rsi, [ rcx + 88 ]     ; ReStoring OG rsi
            mov r12, [ rcx + 96 ]     ; ReStoring OG r12
            mov r13, [ rcx + 104 ]    ; ReStoring OG r13 
            mov r14, [ rcx + 112 ]    ; ReStoring OG r14
            mov r15, [ rcx + 120 ]    ; ReStoring OG r15 
            push rax

            xor rax, rax 
            pop rax
            jmp QWORD [ rcx + 8 ]
