/* Static x86_64 Linux syscall fixture for socket/network side-effect tracing. */

    .section .text
    .global _start
_start:
    mov $41, %rax
    mov $2, %rdi
    mov $2, %rsi
    xor %rdx, %rdx
    syscall
    cmp $0, %rax
    jl fail
    mov %rax, %r12

    mov $44, %rax
    mov %r12, %rdi
    lea payload(%rip), %rsi
    mov $1, %rdx
    xor %r10, %r10
    lea sockaddr(%rip), %r8
    mov $16, %r9
    syscall
    cmp $1, %rax
    jne fail_close

    mov $3, %rax
    mov %r12, %rdi
    syscall

    mov $60, %rax
    xor %rdi, %rdi
    syscall

fail_close:
    mov $3, %rax
    mov %r12, %rdi
    syscall

fail:
    mov $60, %rax
    mov $1, %rdi
    syscall

    .section .rodata
payload:
    .ascii "n"
sockaddr:
    .word 2
    .word 0x0900
    .long 0x0100007f
    .quad 0
