/* Static x86_64 Linux syscall fixture for batched msghdr side-effect tracing. */

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
    mov $2, %rdx
    xor %r10, %r10
    syscall
    cmp $2, %rax
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
payload_a:
    .ascii "a"
payload_b:
    .ascii "b"
sockaddr_a:
    .word 2
    .word 0x0900
    .long 0x0100007f
    .quad 0
sockaddr_b:
    .word 2
    .word 0x0900
    .long 0x0100007f
    .quad 0
    .balign 8
iov_a:
    .quad payload_a
    .quad 1
iov_b:
    .quad payload_b
    .quad 1
    .balign 8
mmsg:
    .quad sockaddr_a
    .long 16
    .long 0
    .quad iov_a
    .quad 1
    .quad 0
    .quad 0
    .long 0
    .long 0
    .long 0
    .long 0
    .quad sockaddr_b
    .long 16
    .long 0
    .quad iov_b
    .quad 1
    .quad 0
    .quad 0
    .long 0
    .long 0
    .long 0
    .long 0
