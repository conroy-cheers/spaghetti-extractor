/* Static x86_64 Linux fixture for per-block memory aggregate tracing. */

    .section .text
    .global _start
_start:
    lea src(%rip), %rsi
    lea dst(%rip), %rdi

    mov 0(%rsi), %rax
    mov %rax, 0(%rdi)
    mov 8(%rsi), %rax
    mov %rax, 8(%rdi)
    mov 16(%rsi), %rax
    mov %rax, 16(%rdi)
    mov 24(%rsi), %rax
    mov %rax, 24(%rdi)
    mov 32(%rsi), %rax
    mov %rax, 32(%rdi)
    mov 40(%rsi), %rax
    mov %rax, 40(%rdi)
    mov 48(%rsi), %rax
    mov %rax, 48(%rdi)
    mov 56(%rsi), %rax
    mov %rax, 56(%rdi)
    mov 64(%rsi), %rax
    mov %rax, 64(%rdi)
    mov 72(%rsi), %rax
    mov %rax, 72(%rdi)
    mov 80(%rsi), %rax
    mov %rax, 80(%rdi)
    mov 88(%rsi), %rax
    mov %rax, 88(%rdi)
    mov 96(%rsi), %rax
    mov %rax, 96(%rdi)
    mov 104(%rsi), %rax
    mov %rax, 104(%rdi)
    mov 112(%rsi), %rax
    mov %rax, 112(%rdi)
    mov 120(%rsi), %rax
    mov %rax, 120(%rdi)
    mov 128(%rsi), %rax
    mov %rax, 128(%rdi)
    mov 136(%rsi), %rax
    mov %rax, 136(%rdi)
    mov 144(%rsi), %rax
    mov %rax, 144(%rdi)
    mov 152(%rsi), %rax
    mov %rax, 152(%rdi)

    mov $60, %rax
    xor %rdi, %rdi
    syscall

    .section .rodata
src:
    .quad 0x0102030405060708
    .quad 0x1112131415161718
    .quad 0x2122232425262728
    .quad 0x3132333435363738
    .quad 0x4142434445464748
    .quad 0x5152535455565758
    .quad 0x6162636465666768
    .quad 0x7172737475767778
    .quad 0x8182838485868788
    .quad 0x9192939495969798
    .quad 0xa1a2a3a4a5a6a7a8
    .quad 0xb1b2b3b4b5b6b7b8
    .quad 0xc1c2c3c4c5c6c7c8
    .quad 0xd1d2d3d4d5d6d7d8
    .quad 0xe1e2e3e4e5e6e7e8
    .quad 0xf1f2f3f4f5f6f7f8
    .quad 0x090a0b0c0d0e0f10
    .quad 0x191a1b1c1d1e1f20
    .quad 0x292a2b2c2d2e2f30
    .quad 0x393a3b3c3d3e3f40

    .section .bss
    .balign 8
dst:
    .skip 160
