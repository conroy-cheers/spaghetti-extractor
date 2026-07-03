/* Static x86_64 Linux syscall fixture for iovec side-effect tracing. */

    .section .text
    .global _start
_start:
    mov $20, %rax
    mov $1, %rdi
    lea iov(%rip), %rsi
    mov $2, %rdx
    syscall
    cmp $2, %rax
    jne fail

    mov $60, %rax
    xor %rdi, %rdi
    syscall

fail:
    mov $60, %rax
    mov $1, %rdi
    syscall

    .section .data
first:
    .ascii "x"
second:
    .ascii "y"
    .balign 8
iov:
    .quad first
    .quad 1
    .quad second
    .quad 1
