/* Static x86_64 Linux syscall fixture for msghdr network side-effect tracing. */

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

    mov $46, %rax
    mov %r12, %rdi
    lea msg(%rip), %rsi
    xor %rdx, %rdx
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

    .section .data
payload:
    .ascii "m"
sockaddr:
    .word 2
    .word 0x0900
    .long 0x0100007f
    .quad 0
    .balign 8
iov:
    .quad payload
    .quad 1
    .balign 8
msg:
    .quad sockaddr
    .long 16
    .long 0
    .quad iov
    .quad 1
    .quad 0
    .quad 0
    .long 0
    .long 0
