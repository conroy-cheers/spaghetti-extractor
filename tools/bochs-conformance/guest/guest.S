#include "../protocol.h"

.section .text
.code16
.global _start

_start:
  cli
  xorw %ax, %ax
  movw %ax, %ds
  movw %ax, %es
  movw %ax, %ss
  movw $BC_HARNESS_STACK_TOP, %sp

  inb $0x92, %al
  orb $0x02, %al
  outb %al, $0x92

  movb $0xff, %al
  outb %al, $0x21
  outb %al, $0xa1

  lgdt gdt_descriptor
  movl %cr0, %eax
  orl $1, %eax
  movl %eax, %cr0
  ljmpl $0x08, $protected_start

.code32
protected_start:
  movw $0x10, %ax
  movw %ax, %ds
  movw %ax, %es
  movw %ax, %ss
  xorw %ax, %ax
  movw %ax, %fs
  movw %ax, %gs
  fninit
  movl $BC_HARNESS_STACK_TOP, %esp
  lidt idt_descriptor
  movl $request_resume, BC_MAILBOX_ADDRESS + BC_MAILBOX_RESUME_EIP

request_resume:
  cli
  cld
  movl $BC_HARNESS_STACK_TOP, %esp
  movw $BC_CONTROL_PORT, %dx
  movl $BC_SIGNAL_READY, %eax
  outl %eax, %dx

  movl BC_MAILBOX_ADDRESS + BC_MAILBOX_STATUS, %eax
  cmpl $BC_MAILBOX_EXECUTE, %eax
  je execute_case
  cmpl $BC_MAILBOX_SKIP, %eax
  je request_resume
  cmpl $BC_MAILBOX_END, %eax
  je guest_done
  jmp guest_failed

execute_case:
  pushl BC_MAILBOX_ADDRESS + BC_MAILBOX_EFLAGS
  popfl
  movl BC_MAILBOX_ADDRESS + BC_MAILBOX_EBX, %ebx
  movl BC_MAILBOX_ADDRESS + BC_MAILBOX_ECX, %ecx
  movl BC_MAILBOX_ADDRESS + BC_MAILBOX_EDX, %edx
  movl BC_MAILBOX_ADDRESS + BC_MAILBOX_ESI, %esi
  movl BC_MAILBOX_ADDRESS + BC_MAILBOX_EDI, %edi
  movl BC_MAILBOX_ADDRESS + BC_MAILBOX_EBP, %ebp
  movl BC_MAILBOX_ADDRESS + BC_MAILBOX_EAX, %eax
  movl BC_MAILBOX_ADDRESS + BC_MAILBOX_ESP, %esp
  jmp *BC_MAILBOX_ADDRESS + BC_MAILBOX_EIP

fault_recover:
  jmp request_resume

guest_done:
  cli
1:
  hlt
  jmp 1b

guest_failed:
  cli
2:
  hlt
  jmp 2b

.align 8
gdt:
  .quad 0x0000000000000000
  .quad 0x00cf9a000000ffff
  .quad 0x00cf92000000ffff
gdt_end:

gdt_descriptor:
  .word gdt_end - gdt - 1
  .long gdt

.align 8
idt:
  .rept 32
    .word fault_recover
    .word 0x0008
    .byte 0
    .byte 0x8e
    .word 0
  .endr
idt_end:

idt_descriptor:
  .word idt_end - idt - 1
  .long idt
