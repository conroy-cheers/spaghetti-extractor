/* Static x86_64 Linux syscall fixture for request-shaped ioctl tracing. */

    .section .text
    .global _start
_start:
    mov $16, %rax
    mov $1, %rdi
    mov $0x541b, %rsi
    lea ioctl_value(%rip), %rdx
    syscall

    mov $60, %rax
    xor %rdi, %rdi
    syscall

    .section .data
ioctl_value:
    .long 0
