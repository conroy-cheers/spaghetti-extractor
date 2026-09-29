/* Diagnostic only: execute the original warning with controlled entry bytes.
 * No authored replacement is selected and no equivalence is claimed. */
#include <windows.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "native-image.h"
uint32_t warning_residue[3] __attribute__((used));
static uint32_t sprite[12],queued[2],exploded[2],queue_calls,explosion_calls,particle_calls;
static uint32_t *word(uint32_t address) { return (uint32_t *)(uintptr_t)address; }
static void require(int test) { if (!test) ExitProcess(86); }
static DWORD WINAPI now(void) { return 2; }
static uint32_t random_value(uint32_t limit) { require(limit!=0); return 0; }
static void sound_stop(uint32_t sound) { (void)sound; }
static void sound_play(uint32_t a,uint32_t b,uint32_t c,uint32_t d) { (void)a;(void)b;(void)c;(void)d; }
static uint32_t pan(uint32_t x) { (void)x; return 0; }
static void destination(uint32_t surface) { (void)surface; }
static void cell(uint32_t column,uint32_t row,uint32_t mode) { (void)column;(void)row;(void)mode; }
static void queue(uint32_t column,uint32_t row) { ++queue_calls; queued[0]=column;queued[1]=row; }
static void explosion(uint32_t x,uint32_t y) { ++explosion_calls; exploded[0]=x;exploded[1]=y; }
static void particle(uint32_t x,uint32_t y,uint32_t dx,uint32_t dy,uint32_t color,uint32_t gravity) {
    (void)x;(void)y;(void)dx;(void)dy;(void)color;(void)gravity; ++particle_calls;
}
static void select_bank(uint32_t bank) { *word(0x434968)=bank; }
/* The jmp preserves the original entry ESP and return address. Its reserved
 * locals at entry ESP-28/-24/-20 have deliberately controlled prior contents.
 * If the scan finds no eligible cell, these supply y/row/column and also x. */
static void __attribute__((naked)) enter_warning(void) {
    __asm__ volatile(
        "movl _warning_residue, %eax\n\tmovl %eax, -28(%esp)\n\t"
        "movl _warning_residue+4, %eax\n\tmovl %eax, -24(%esp)\n\t"
        "movl _warning_residue+8, %eax\n\tmovl %eax, -20(%esp)\n\t"
        "movl $0x408c20, %eax\n\tjmp *%eax\n\t");
}
static int run(int argc,char **argv) {
    require(argc==5); uint32_t tile=(uint32_t)strtoul(argv[1],NULL,0);
    for (unsigned i=0;i<3;++i) warning_residue[i]=(uint32_t)strtoul(argv[i+2],NULL,0);
    memset((void *)0x42ca60,0,400); ((unsigned char *)0x42ca60)[21]=(unsigned char)tile;
    uint32_t initial=((uint32_t (*)(void))0x408900)(); *word(0x431c48)=initial;
    if (tile>22) ((uint32_t (*)(uint32_t,uint32_t))0x405c80)(1,1);
    uint32_t counted=((uint32_t (*)(void))0x408900)(),remaining=*word(0x431c48);
    *word(0x42cdd4)=1; *word(0x4349c8)=1;
    sprite[2]=159;sprite[3]=479; *word(0x433d1c+2*1048)=(uint32_t)(uintptr_t)sprite;
    enter_warning();
    printf("{\"tile\":%u,\"initial_count\":%u,\"current_count\":%u,\"remaining\":%u,\"entry_words\":[%u,%u,%u],\"queue\":[%u,%u],\"explosion\":[%u,%u],\"calls\":[%u,%u,%u],\"warning_frames\":%u,\"rectangle\":[%u,%u,%u,%u]}\n",
        tile,initial,counted,remaining,warning_residue[0],warning_residue[1],warning_residue[2],queued[0],queued[1],exploded[0],exploded[1],
        queue_calls,explosion_calls,particle_calls,*word(0x431cb0),*word(0x42cda0),*word(0x42cda4),*word(0x42cda8),*word(0x42cdac));
    fflush(NULL);return 0;
}
__declspec(dllexport) void dx_warning_probe_anchor(void) {}
static void startup(void) {
    int argc=0,startup_info=0;char **argv=NULL,**environment=NULL;
    extern int __cdecl __getmainargs(int *,char ***,char ***,int,int *);
    __getmainargs(&argc,&argv,&environment,0,&startup_info); ExitProcess((UINT)run(argc,argv));
}
BOOL WINAPI DllMain(HINSTANCE instance,DWORD reason,void *reserved) {
    (void)instance;(void)reserved;if (reason!=DLL_PROCESS_ATTACH) return TRUE;
#define HOOK(name,replacement) require(install_##name((void (*)(void))replacement))
    HOOK(startup,startup);HOOK(random,random_value);HOOK(stop_sound,sound_stop);HOOK(play_sound,sound_play);
    HOOK(loop_sound,sound_play);HOOK(queue,queue);HOOK(explosion,explosion);HOOK(particle,particle);
    HOOK(select_bank,select_bank);HOOK(pan,pan);HOOK(destination,destination);HOOK(cell,cell);
#undef HOOK
    DWORD old,ignored;require(VirtualProtect((void *)0x415174,4,PAGE_READWRITE,&old));
    *word(0x415174)=(uint32_t)(uintptr_t)now;require(VirtualProtect((void *)0x415174,4,old,&ignored));
    return TRUE;
}
