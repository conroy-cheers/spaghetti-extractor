.section .text
.code16
.global _start

_start:
  cli
  xorw %ax, %ax
  movw %ax, %ds
  movw %ax, %es
  movw %ax, %ss
  movw $0x7c00, %sp
  movb %dl, boot_drive
  sti

  movw $0x1000, %bx
  movb $0x02, %ah
  movb $16, %al
  movb $0, %ch
  movb $2, %cl
  movb $0, %dh
  movb boot_drive, %dl
  int $0x13
  jc boot_failed
  ljmp $0x0000, $0x1000

boot_failed:
  cli
1:
  hlt
  jmp 1b

boot_drive:
  .byte 0

.org 510
.word 0xaa55
