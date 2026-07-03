/* Static x86_64 Linux syscall fixture for fd/resource side-effect tracing. */

    .section .text
    .global _start
_start:
    mov $2, %rax
    lea path(%rip), %rdi
    mov $577, %rsi
    mov $0644, %rdx
    syscall

    mov %rax, %r12
    cmp $0, %rax
    jl fail

    mov $1, %rax
    mov %r12, %rdi
    lea payload(%rip), %rsi
    mov $1, %rdx
    syscall
    cmp $1, %rax
    jne fail

    mov $3, %rax
    mov %r12, %rdi
    syscall

    mov $60, %rax
    xor %rdi, %rdi
    syscall

fail:
    mov $60, %rax
    mov $1, %rdi
    syscall

    .section .rodata
path:
    .asciz "/tmp/wfdo"
payload:
    .ascii "z"
