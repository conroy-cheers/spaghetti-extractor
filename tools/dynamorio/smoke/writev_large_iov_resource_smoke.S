/* Static x86_64 Linux syscall fixture for oversized iovec aggregate tracing. */

    .section .text
    .global _start
_start:
    mov $20, %rax
    mov $1, %rdi
    lea iov(%rip), %rsi
    mov $10, %rdx
    syscall
    cmp $10, %rax
    jne fail

    mov $60, %rax
    xor %rdi, %rdi
    syscall

fail:
    mov $60, %rax
    mov $1, %rdi
    syscall

    .section .rodata
payload:
    .ascii "0123456789"

    .section .data
    .balign 8
iov:
    .quad payload + 0
    .quad 1
    .quad payload + 1
    .quad 1
    .quad payload + 2
    .quad 1
    .quad payload + 3
    .quad 1
    .quad payload + 4
    .quad 1
    .quad payload + 5
    .quad 1
    .quad payload + 6
    .quad 1
    .quad payload + 7
    .quad 1
    .quad payload + 8
    .quad 1
    .quad payload + 9
    .quad 1
