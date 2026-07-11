.intel_syntax noprefix

.section .text
.global _mainCRTStartup

_mainCRTStartup:
    call dword ptr [__imp__GetTickCount@0]
    ret
    .balign 16, 0x90

_stage_a_internal_caller:
    call _stage_a_internal_callee
    ret
    .balign 16, 0x90

_stage_a_internal_callee:
#ifdef STAGE_A_VARIANT_B
    lea eax, [ebx]
#else
    mov eax, ebx
#endif
    ret
    .balign 16, 0x90
