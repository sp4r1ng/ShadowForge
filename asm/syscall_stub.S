    .text
    .global DoSyscall
    .def DoSyscall; .scl 2; .type 32; .endef

DoSyscall:
    mov     %ecx, %eax
    mov     %rdx, %r10
    mov     %r8, %rdx
    mov     %r9, %r8
    mov     0x28(%rsp), %r9
    mov     0x30(%rsp), %rcx
    mov     %rcx, 0x28(%rsp)
    mov     0x38(%rsp), %rcx
    mov     %rcx, 0x30(%rsp)
    syscall
    ret
