    .intel_syntax noprefix

    .section .rdata,"dr"
message:
    .ascii "Hello, world!\r\n"
    .set message_len, . - message
unused_fixture_marker:
#ifdef STAGE_A_CANDIDATE
    .byte 1
#else
    .byte 0
#endif

    .section .data
    .balign 4
written:
    .long 0

    .text
    .globl _mainCRTStartup
    .globl _stageASetup
    .globl _stageAGet
    .globl _stageAAfterGet
    .globl _stageAWriteConstants
    .globl _stageAWriteCall
    .globl _stageAExit
    .extern "_GetStdHandle@4"
    .extern "_WriteFile@20"
    .extern "_ExitProcess@4"

_mainCRTStartup:
    jmp _stageASetup

_stageASetup:
    sub esp, 24
    jmp _stageAGet

_stageAGet:
    mov DWORD PTR [esp], -11
    call "_GetStdHandle@4"

_stageAAfterGet:
    sub esp, 4
    jmp _stageAWriteConstants

_stageAWriteConstants:
    mov DWORD PTR [esp + 16], 0
    mov DWORD PTR [esp + 12], OFFSET FLAT:written
    mov DWORD PTR [esp + 8], message_len
    mov DWORD PTR [esp + 4], OFFSET FLAT:message
    jmp _stageAWriteCall

_stageAWriteCall:
    mov DWORD PTR [esp], eax
    call "_WriteFile@20"

_stageAExit:
    mov DWORD PTR [esp], 0
    call "_ExitProcess@4"
