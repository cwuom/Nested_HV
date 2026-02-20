; Created by cwuom on 17 Feb 2026.

.code

extern VmExitHandler:proc

; ------------------------------------------------------------------------------
; HvVmExitEntryPoint
; handles the transition from guest to host
; ------------------------------------------------------------------------------
HvVmExitEntryPoint proc
    sub rsp, 1100h

    mov [rsp + 1000h], rax
    mov [rsp + 1008h], rcx
    mov [rsp + 1010h], rdx
    mov [rsp + 1018h], rbx
    mov [rsp + 1020h], rbp
    mov [rsp + 1028h], rsi
    mov [rsp + 1030h], rdi
    mov [rsp + 1038h], r8
    mov [rsp + 1040h], r9
    mov [rsp + 1048h], r10
    mov [rsp + 1050h], r11
    mov [rsp + 1058h], r12
    mov [rsp + 1060h], r13
    mov [rsp + 1068h], r14
    mov [rsp + 1070h], r15

    xor ecx, ecx
    xgetbv

    xsave [rsp]

    mov rcx, rsp

    sub rsp, 20h
    call VmExitHandler
    add rsp, 20h

    xor ecx, ecx
    xgetbv              ; load XCR0 mask into EDX:EAX

    xrstor [rsp]

    mov rax, [rsp + 1000h]
    mov rcx, [rsp + 1008h]
    mov rdx, [rsp + 1010h]
    mov rbx, [rsp + 1018h]
    mov rbp, [rsp + 1020h]
    mov rsi, [rsp + 1028h]
    mov rdi, [rsp + 1030h]
    mov r8,  [rsp + 1038h]
    mov r9,  [rsp + 1040h]
    mov r10, [rsp + 1048h]
    mov r11, [rsp + 1050h]
    mov r12, [rsp + 1058h]
    mov r13, [rsp + 1060h]
    mov r14, [rsp + 1068h]
    mov r15, [rsp + 1070h]

    add rsp, 1100h

    vmresume
    int 3
    ret
HvVmExitEntryPoint endp

; ------------------------------------------------------------------------------
; HvRestoreStateAndReturn
; Called ONLY during Unload.
; RCX = Pointer to GuestContext
; ------------------------------------------------------------------------------
HvRestoreStateAndReturn proc
    vmxoff

    mov rax, cr4
    btr rax, 13
    mov cr4, rax

    mov rbx, rcx

    xor ecx, ecx
    xgetbv
    xrstor [rbx]

    mov rax, [rbx + 1000h]
    mov rcx, [rbx + 1008h]
    mov rdx, [rbx + 1010h]
    mov r8,  [rbx + 1038h]
    mov r9,  [rbx + 1040h]
    mov r10, [rbx + 1048h]
    mov r11, [rbx + 1050h]
    mov r12, [rbx + 1058h]
    mov r13, [rbx + 1060h]
    mov r14, [rbx + 1068h]
    mov r15, [rbx + 1070h]
    mov rbp, [rbx + 1020h]
    mov rsi, [rbx + 1028h]
    mov rdi, [rbx + 1030h]

    mov rax, [rbx + 1018h]

    mov dx, ss
    movzx rdx, dx
    push rdx

    mov rdx, [rbx + 1080h]
    push rdx

    mov rdx, [rbx + 1088h]
    push rdx

    mov dx, cs
    movzx rdx, dx
    push rdx

    mov rdx, [rbx + 1078h]
    push rdx

    mov rbx, rax

    iretq
HvRestoreStateAndReturn endp

; standard VMX intrinsics
HvVmxOn proc
    vmxon qword ptr [rcx]
    pushfq
    pop rax
    ret
HvVmxOn endp

HvVmxOff proc
    vmxoff
    ret
HvVmxOff endp

HvVmClear proc
    vmclear qword ptr [rcx]
    pushfq
    pop rax
    ret
HvVmClear endp

HvVmPtrLd proc
    vmptrld qword ptr [rcx]
    pushfq
    pop rax
    ret
HvVmPtrLd endp

HvVmWrite proc
    vmwrite rcx, rdx
    pushfq
    pop rax
    ret
HvVmWrite endp

HvVmRead proc
    vmread rax, rcx
    ret
HvVmRead endp

HvLaunchGuest proc
    vmlaunch
    pushfq
    pop rax
    ret
HvLaunchGuest endp

; Segment Helpers
GetCs proc
    mov ax, cs
    ret
GetCs endp
GetDs proc
    mov ax, ds
    ret
GetDs endp
GetEs proc
    mov ax, es
    ret
GetEs endp
GetSs proc
    mov ax, ss
    ret
GetSs endp
GetFs proc
    mov ax, fs
    ret
GetFs endp
GetGs proc
    mov ax, gs
    ret
GetGs endp
GetTr proc
    str ax
    ret
GetTr endp
GetLdtr proc
    sldt ax
    ret
GetLdtr endp
GetGdtBase proc
    sub rsp, 10h
    sgdt [rsp]
    mov rax, [rsp+2]
    add rsp, 10h
    ret
GetGdtBase endp
GetGdtLimit proc
    sub rsp, 10h
    sgdt [rsp]
    mov ax, [rsp]
    add rsp, 10h
    ret
GetGdtLimit endp
GetIdtBase proc
    sub rsp, 10h
    sidt [rsp]
    mov rax, [rsp+2]
    add rsp, 10h
    ret
GetIdtBase endp
GetIdtLimit proc
    sub rsp, 10h
    sidt [rsp]
    mov ax, [rsp]
    add rsp, 10h
    ret
GetIdtLimit endp
GetRflags proc
    pushfq
    pop rax
    ret
GetRflags endp

; u32 HvGetSegmentLimit(u16 Selector)
HvGetSegmentLimit proc
    lsl eax, ecx
    jz  Success
    xor eax, eax
Success:
    ret
HvGetSegmentLimit endp

; u32 HvGetSegmentAr(u16 Selector)
HvGetSegmentAr proc
    lar eax, ecx
    jz Success
    mov eax, 10000h
    ret
Success:
    shr eax, 8
    and eax, 0F0FFh
    ret
HvGetSegmentAr endp

; ------------------------------------------------------------------------------
; Guest Start Thunk
; ------------------------------------------------------------------------------
GuestStartThunk proc
    ret
GuestStartThunk endp

; ------------------------------------------------------------------------------
; HvCall (VMCALL Wrapper)
; RCX = Magic, RDX = Command, R8 = Arg1, R9 = Arg2
; ------------------------------------------------------------------------------
HvCall proc
    vmcall
    xor rax, rax
    ret
HvCall endp

end