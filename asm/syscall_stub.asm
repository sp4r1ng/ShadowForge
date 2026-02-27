.code

DoSyscall PROC
    mov     eax, ecx
    mov     r10, rdx
    mov     rdx, r8
    mov     r8, r9
    mov     r9, qword ptr [rsp + 28h]
    mov     rcx, qword ptr [rsp + 30h]
    mov     qword ptr [rsp + 28h], rcx
    mov     rcx, qword ptr [rsp + 38h]
    mov     qword ptr [rsp + 30h], rcx
    syscall
    ret
DoSyscall ENDP

END
