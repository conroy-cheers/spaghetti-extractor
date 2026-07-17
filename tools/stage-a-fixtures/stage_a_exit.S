    .text
    .globl _mainCRTStartup
    .extern "_ExitProcess@4"
_mainCRTStartup:
#ifdef STAGE_A_CANDIDATE
    xorl %eax, %eax
    addl $42, %eax
#else
    movl $42, %eax
#endif
    movl %eax, (%esp)
    call "_ExitProcess@4"
