/* The paddle-produced warning coordinate (0,84) reads a saved-board byte.
 * Execute the original queue with that byte empty/nonempty and observe its event.
 * This does not run the existing portable queue outside its admitted domain. */
#define run residue_run
#define startup residue_startup
#define DllMain residue_DllMain
#include "entry-residue.c"
#undef DllMain
#undef startup
#undef run

static uint32_t event[5],allocations;
static uint32_t allocate(uint32_t size) {
    require(size==20 && allocations++==0);return (uint32_t)(uintptr_t)event;
}
static int run(int argc,char **argv) {
    require(argc==2);uint32_t byte=(uint32_t)strtoul(argv[1],NULL,10);require(byte==0 || byte==7);
    memset((void *)0x42ca60,0,400);memset((void *)0x42cdf8,0,20000);
    const uint32_t address=UINT32_C(0x42ca60)+84*20;
    *(unsigned char *)(uintptr_t)address=(unsigned char)byte;
    *word(0x431c38)=*word(0x431c3c)=*word(0x431c40)=*word(0x431cc4)=0;
    ((void (*)(uint32_t,uint32_t))0x406410)(0,84);
    for (unsigned i=0;i<400;++i) require(((unsigned char *)0x42ca60)[i]==0);
    require(allocations==(byte!=0));
    if (allocations) {
        require(*word(0x431c38)==(uint32_t)(uintptr_t)event && *word(0x431c3c)==*word(0x431c38)
            && *word(0x431c40)==*word(0x431c38) && event[0]==1 && event[1]==0 && event[2]==84
            && !event[3] && !event[4]);
    } else require(!*word(0x431c38) && !*word(0x431c3c) && !*word(0x431c40));
    printf("{\"queue\":[0,84],\"address\":%u,\"saved_byte_offset\":%u,\"saved_byte\":%u,\"active_board_nonzero\":0,\"allocations\":%u,\"voice_pending\":%u,\"event\":[%u,%u,%u,%u,%u]}\n",
        address,address-0x42cdf8,byte,allocations,*word(0x431cc4),event[0],event[1],event[2],event[3],event[4]);
    fflush(NULL);return 0;
}
static void startup(void) {
    int argc=0,startup_info=0;char **argv=NULL,**environment=NULL;
    extern int __cdecl __getmainargs(int *,char ***,char ***,int,int *);
    __getmainargs(&argc,&argv,&environment,0,&startup_info);ExitProcess((UINT)run(argc,argv));
}
BOOL WINAPI DllMain(HINSTANCE instance,DWORD reason,void *reserved) {
    (void)instance;(void)reserved;if (reason!=DLL_PROCESS_ATTACH) return TRUE;
    require(install_startup(startup));require(install_allocate((void (*)(void))allocate));return TRUE;
}
