/* Static x86_64 Linux fixture for repeated syscall side-effect tracing. */

    .section .text
    .global _start
_start:
    .rept 20
    mov $39, %rax
    syscall
    .endr

    mov $60, %rax
    xor %rdi, %rdi
    syscall
