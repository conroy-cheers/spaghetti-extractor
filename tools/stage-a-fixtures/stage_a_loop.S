.intel_syntax noprefix

.section .text
.global _mainCRTStartup

_mainCRTStartup:
    jmp _mainCRTStartup
