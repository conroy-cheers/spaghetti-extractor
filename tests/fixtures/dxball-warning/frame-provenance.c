/* Native-only connected consumer. The real frame, paddle/sprite/pickup/particle
 * drawing and warning bodies run; other services have explicit controlled inputs.
 * Reuse the preceding diagnostic's audio/effect hooks and process entry glue. */
#define run residue_run
#define startup residue_startup
#define DllMain residue_DllMain
#include "entry-residue.c"
#undef DllMain
#undef startup
#undef run

uint32_t frame_inputs[2] __attribute__((used));
static uint32_t mode,observed_warning,describes,locks,blits,damages;
static uint32_t vtable[33],surface,ordinary_sprite[12],ball[15],pickup[9],trail[11];
static unsigned char pixels[640*480];

/* Set only the frame's incoming EBP/ESI; the frame and its real callees produce
 * all three warning words. Keep the surrounding C caller's saved registers. */
static void __attribute__((naked)) enter_frame(void) {
    __asm__ volatile(
        "pushl %ebx\n\tpushl %ebp\n\tpushl %esi\n\tpushl %edi\n\t"
        "movl _frame_inputs, %ebp\n\tmovl _frame_inputs+4, %esi\n\t"
        "movl $0x4044d0, %eax\n\tcall *%eax\n\t"
        "popl %edi\n\tpopl %esi\n\tpopl %ebp\n\tpopl %ebx\n\tret\n\t");
}

/* The frame's call at 404626 is redirected here. Reading into globals and then
 * jumping leaves its original entry ESP, return address and stack bytes intact.
 * EAX is overwritten immediately by the original warning's first instruction. */
static void __attribute__((naked)) observe_warning(void) {
    __asm__ volatile(
        "incl _observed_warning\n\t"
        "movl -28(%esp), %eax\n\tmovl %eax, _warning_residue\n\t"
        "movl -24(%esp), %eax\n\tmovl %eax, _warning_residue+4\n\t"
        "movl -20(%esp), %eax\n\tmovl %eax, _warning_residue+8\n\t"
        "movl $0x408c20, %eax\n\tjmp *%eax\n\t");
}
static void install_warning_observer(void) {
    unsigned char *call=(unsigned char *)0x404626;
    const unsigned char expected[]={0xe8,0xf5,0x45,0,0};
    require(!memcmp(call,expected,sizeof(expected)));
    DWORD old,ignored;require(VirtualProtect(call,5,PAGE_EXECUTE_READWRITE,&old));
    uint32_t delta=(uint32_t)(uintptr_t)observe_warning-0x40462b;
    memcpy(call+1,&delta,4);
    require(VirtualProtect(call,5,old,&ignored));require(FlushInstructionCache(GetCurrentProcess(),call,5));
}
static void __attribute__((naked)) no_op(void) { __asm__ volatile("ret"); }
static uint32_t elapsed(uint32_t previous,uint32_t delay) { (void)previous;(void)delay;return 0; }
static uint32_t WINAPI blit(uint32_t target,uint32_t x,uint32_t y,uint32_t source,void *rect,uint32_t flags) {
    (void)x;(void)y;(void)rect;require(target==(uint32_t)(uintptr_t)&surface && source==target);
    require(flags==16 || flags==17);++blits;return 0;
}
static void damage(uint32_t x,uint32_t y,uint32_t right,uint32_t bottom) {
    (void)x;(void)y;(void)right;(void)bottom;++damages;
}
static void fill_descriptor(uint32_t *desc,int locking) {
    require(desc[0]==108);
    desc[2]=480;desc[3]=640;desc[4]=640;desc[9]=(uint32_t)(uintptr_t)pixels;
    /* These offsets coincide with the warning's future local words. Mode 4
     * deliberately preserves fields across partial service writes. */
    if (mode==4) {
        if (locking) desc[21]=5;
        else { desc[20]=120;desc[21]=2; }
    } else { desc[20]=120;desc[21]=2;desc[22]=3; }
}
static uint32_t WINAPI describe(uint32_t target,uint32_t *desc) {
    require(target==(uint32_t)(uintptr_t)&surface);++describes;fill_descriptor(desc,0);return 0;
}
static uint32_t WINAPI lock_surface(uint32_t target,void *rect,uint32_t *desc,uint32_t flags,void *event) {
    require(target==(uint32_t)(uintptr_t)&surface && !rect && !flags && !event);
    ++locks;fill_descriptor(desc,1);return 0;
}
static uint32_t WINAPI unlock_surface(uint32_t target,void *data) {
    require(target==(uint32_t)(uintptr_t)&surface && !data);return 0;
}
static int run(int argc,char **argv) {
    require(argc==2);mode=(uint32_t)strtoul(argv[1],NULL,10);require(mode<8);
    frame_inputs[0]=mode>=6 ? *word(0x415148) : 2;
    frame_inputs[1]=mode>=6 ? *word(0x415164) : 120;
    memset((void *)0x42ca60,0,400);((unsigned char *)0x42ca60)[21]=23;
    uint32_t initial=((uint32_t (*)(void))0x408900)();*word(0x431c48)=initial;
    ((uint32_t (*)(uint32_t,uint32_t))0x405c80)(1,1);
    uint32_t counted=((uint32_t (*)(void))0x408900)();
    require(initial==1 && counted==0 && *word(0x431c48)==1);
    vtable[7]=(uint32_t)(uintptr_t)blit;vtable[22]=(uint32_t)(uintptr_t)describe;
    vtable[25]=(uint32_t)(uintptr_t)lock_surface;vtable[32]=(uint32_t)(uintptr_t)unlock_surface;
    surface=(uint32_t)(uintptr_t)vtable;*word(0x41c728)=(uint32_t)(uintptr_t)&surface;
    ordinary_sprite[0]=(uint32_t)(uintptr_t)&surface;ordinary_sprite[2]=10;ordinary_sprite[3]=20;
    ordinary_sprite[7]=10;ordinary_sprite[8]=20;
    for (unsigned i=0;i<256;++i) *word(0x433d18+4*i)=(uint32_t)(uintptr_t)ordinary_sprite;
    sprite[2]=159;sprite[3]=479;*word(0x433d1c+2*1048)=(uint32_t)(uintptr_t)sprite;
    *word(0x434968)=0;*word(0x4349c8)=1;*word(0x42cdd4)=1;
    *word(0x431c74)=0;*word(0x417a04)=0;*word(0x431c6c)=0;*word(0x434990)=0;
    *word(0x431c78)=50;*word(0x431c84)=68;*word(0x431c64)=0;
    *word(0x42cdec)=300;*word(0x42cdf0)=450;
    ball[0]=50;ball[1]=60;ball[6]=1;
    pickup[1]=3;pickup[2]=100;pickup[3]=200;
    trail[0]=30;trail[1]=40;trail[6]=16;
    *word(0x431c24)=(mode==1 || mode==5 || mode==6) ? (uint32_t)(uintptr_t)ball : 0;
    *word(0x431c54)=(mode==2 || mode==5 || mode==7) ? (uint32_t)(uintptr_t)pickup : 0;
    *word(0x42ca2c)=(mode==3 || mode==4) ? (uint32_t)(uintptr_t)trail : 0;
    *word(0x42cddc)=0;*word(0x431c3c)=0;*word(0x431cc4)=0;
    for (uint32_t address=0x431c88;address<=0x431c90;address+=4) *word(address)=0;
    *word(0x431c94)=0;*word(0x431cb4)=0;
    enter_frame();require(observed_warning==1);
    uint32_t address=UINT32_C(0x42ca60)+queued[1]*20+queued[0];
    printf("{\"mode\":%u,\"count_transition\":[%u,%u,%u],\"incoming_ebp_esi\":[%u,%u],\"entry_words\":[%u,%u,%u],\"queue\":[%u,%u],\"queue_within_grid\":%s,\"queue_address\":%u,\"explosion\":[%u,%u],\"warning_calls\":[%u,%u,%u],\"drawing_calls\":[%u,%u,%u,%u]}\n",
        mode,initial,counted,*word(0x431c48),frame_inputs[0],frame_inputs[1],
        warning_residue[0],warning_residue[1],warning_residue[2],queued[0],queued[1],
        queued[0]<20 && queued[1]<20 ? "true" : "false",address,exploded[0],exploded[1],
        queue_calls,explosion_calls,particle_calls,blits,describes,locks,damages);
    fflush(NULL);return 0;
}
static void startup(void) {
    int argc=0,startup_info=0;char **argv=NULL,**environment=NULL;
    extern int __cdecl __getmainargs(int *,char ***,char ***,int,int *);
    __getmainargs(&argc,&argv,&environment,0,&startup_info);ExitProcess((UINT)run(argc,argv));
}
BOOL WINAPI DllMain(HINSTANCE instance,DWORD reason,void *reserved) {
    (void)instance;(void)reserved;if (reason!=DLL_PROCESS_ATTACH) return TRUE;
#define HOOK(name,replacement) require(install_##name((void (*)(void))replacement))
    HOOK(startup,startup);HOOK(random,random_value);HOOK(stop_sound,sound_stop);HOOK(play_sound,sound_play);
    HOOK(loop_sound,sound_play);HOOK(queue,queue);HOOK(explosion,explosion);HOOK(particle,particle);
    HOOK(select_bank,select_bank);HOOK(pan,pan);HOOK(destination,destination);HOOK(cell,cell);
    HOOK(elapsed,elapsed);HOOK(damage,damage);
    HOOK(refresh_score,no_op);HOOK(move_paddle,no_op);HOOK(move_balls,no_op);HOOK(move_shots,no_op);
    HOOK(move_pickups,no_op);HOOK(move_trails,no_op);HOOK(wait,no_op);HOOK(restore_damage,no_op);
    HOOK(advance_effects,no_op);HOOK(draw_explosions,no_op);HOOK(draw_warning,no_op);HOOK(present,no_op);
    HOOK(advance_stage,no_op);
#undef HOOK
    DWORD old,ignored;require(VirtualProtect((void *)0x415174,4,PAGE_READWRITE,&old));
    *word(0x415174)=(uint32_t)(uintptr_t)now;require(VirtualProtect((void *)0x415174,4,old,&ignored));
    install_warning_observer();return TRUE;
}
