.intel_syntax noprefix

.section .text
.global _mainCRTStartup

_mainCRTStartup:
#ifdef STAGE_A_VARIANT_B
    lea eax, [ebx]
    sub eax, 0
    .byte 0xff, 0xf0
    .byte 0x8f, 0xc3
#else
    mov eax, ebx
    add eax, 0
    push eax
    pop ebx
#endif
    ret
    .balign 16, 0x90

_stage_a_memory_case:
#ifdef STAGE_A_VARIANT_B
    mov eax, [esi + 0]
    lea edx, [edi + 4]
    mov [edi + 4], eax
#else
    lea edx, [edi + 4]
    mov eax, [esi]
    mov [edx], eax
#endif
    ret
    .balign 16, 0x90

_stage_a_zero_case:
#ifdef STAGE_A_VARIANT_B
    xor eax, eax
#elif defined(STAGE_A_MUTATION)
    mov eax, 1
#else
    sub eax, eax
#endif
    ret
    .balign 16, 0x90

#ifndef STAGE_A_NO_EXTERNAL
_stage_a_external_case:
#ifdef STAGE_A_VARIANT_B
    sub eax, eax
#else
    xor eax, eax
#endif
    call dword ptr [__imp__GetTickCount@0]
    ret
    .balign 16, 0x90
#endif

#ifndef STAGE_A_NO_BRANCH
_stage_a_branch_case:
    cmp eax, 7
    je _stage_a_branch_taken
#ifdef STAGE_A_VARIANT_B
    lea edx, [ebx]
#else
    mov edx, ebx
#endif
    ret

_stage_a_branch_taken:
#ifdef STAGE_A_VARIANT_B
    mov edx, 7
#else
    mov edx, eax
    nop
    nop
    nop
#endif
    ret
    .balign 16, 0x90
#endif
