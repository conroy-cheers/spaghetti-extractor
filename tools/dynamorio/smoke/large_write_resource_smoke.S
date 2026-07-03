/* Static x86_64 Linux syscall fixture for large-buffer digest tracing. */

    .section .text
    .global _start
_start:
    mov $1, %rax
    mov $1, %rdi
    lea payload(%rip), %rsi
    mov $96, %rdx
    syscall
    cmp $96, %rax
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
    .rept 96
    .byte 0x4c
    .endr
