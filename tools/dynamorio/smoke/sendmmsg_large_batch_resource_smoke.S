/* Static x86_64 Linux syscall fixture for oversized sendmmsg aggregate tracing. */

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

    mov $307, %rax
    mov %r12, %rdi
    lea mmsg(%rip), %rsi
    mov $5, %rdx
    xor %r10, %r10
    syscall
    cmp $5, %rax
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
    .ascii "0123456789abcde"
sockaddr:
    .word 2
    .word 0x0900
    .long 0x0100007f
    .quad 0
    .balign 8
iov_0:
    .quad payload + 0
    .quad 1
    .quad payload + 1
    .quad 1
    .quad payload + 2
    .quad 1
iov_1:
    .quad payload + 3
    .quad 1
    .quad payload + 4
    .quad 1
    .quad payload + 5
    .quad 1
iov_2:
    .quad payload + 6
    .quad 1
    .quad payload + 7
    .quad 1
    .quad payload + 8
    .quad 1
iov_3:
    .quad payload + 9
    .quad 1
    .quad payload + 10
    .quad 1
    .quad payload + 11
    .quad 1
iov_4:
    .quad payload + 12
    .quad 1
    .quad payload + 13
    .quad 1
    .quad payload + 14
    .quad 1
    .balign 8
mmsg:
    .quad sockaddr
    .long 16
    .long 0
    .quad iov_0
    .quad 3
    .quad 0
    .quad 0
    .long 0
    .long 0
    .long 0
    .long 0
    .quad sockaddr
    .long 16
    .long 0
    .quad iov_1
    .quad 3
    .quad 0
    .quad 0
    .long 0
    .long 0
    .long 0
    .long 0
    .quad sockaddr
    .long 16
    .long 0
    .quad iov_2
    .quad 3
    .quad 0
    .quad 0
    .long 0
    .long 0
    .long 0
    .long 0
    .quad sockaddr
    .long 16
    .long 0
    .quad iov_3
    .quad 3
    .quad 0
    .quad 0
    .long 0
    .long 0
    .long 0
    .long 0
    .quad sockaddr
    .long 16
    .long 0
    .quad iov_4
    .quad 3
    .quad 0
    .quad 0
    .long 0
    .long 0
    .long 0
    .long 0
