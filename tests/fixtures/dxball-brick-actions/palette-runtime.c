/* Native frame/elapsed/palette helpers with explicit time, without game startup. */
#define main controlled_frame_main
#define DllMain controlled_frame_dll_main
#define play_elapsed controlled_play_elapsed
#define play_now controlled_play_now
#define play_cycle controlled_play_cycle
#include "frame-local-runtime.c"
#undef main
#undef DllMain
#undef play_elapsed
#undef play_now
#undef play_cycle

static uint32_t palette_clock,palette_calls,palette_table[7],palette_object;
static uint32_t palette_now(void) {
    play_from_native(); begin_call(&play,PLAY_NOW,NULL,0);
    uint32_t result=end_call(palette_clock); play_to_native(); return result;
}
static uint32_t WINAPI palette_apply(uint32_t object,uint32_t flags,uint32_t first,uint32_t count,void *entries) {
    REQUIRE(object==(uint32_t)(uintptr_t)&palette_object && !flags && first+count<=256);
    REQUIRE(entries==(void *)(uintptr_t)(0x42c148+4*first)); ++palette_calls;
    play_from_native(); const uint32_t args[]={first,count}; begin_call(&play,PLAY_CYCLE,args,2);
    spx_observe_bytes(observer,"palette",entries,count*4); (void)end_call(0); play_to_native(); return 0;
}
uint32_t play_elapsed(void *user,play_state *s,uint32_t previous,uint32_t delay) {
    (void)user; REQUIRE(s==&play); play_to_native();
    uint32_t result=((uint32_t (*)(uint32_t,uint32_t))0x40db80)(previous,delay); play_from_native(); return result;
}
uint32_t play_now(void *user,play_state *s) { (void)user; REQUIRE(s==&play); play_to_native(); return palette_now(); }
void play_cycle(void *user,play_state *s,uint32_t first,uint32_t last,uint32_t amount) {
    (void)user; REQUIRE(s==&play); play_to_native();
    ((void (*)(uint32_t,uint32_t,uint32_t))0x402af0)(first,last,amount); play_from_native();
}
int main(int argc,char **argv) {
    REQUIRE(argc==3); unsigned scenario=(unsigned)strtoul(argv[2],NULL,10); REQUIRE(scenario<4);
    int source=!strcmp(argv[1],"source"); setup(2); play.paused=scenario<2; play.last_tick=100;
    palette_clock=100+(play.paused ? 32 : 20)-(scenario%2==0);
#ifdef PALETTE_UNEQUAL_INPUT
    if (source) ++palette_clock;
#endif
    install(source); play_to_native();
    REQUIRE(spx_fixture_restore_entry(&install_play_service_elapsed_hook));
    REQUIRE(spx_fixture_restore_entry(&install_play_service_cycle_hook));
    REQUIRE(spx_fixture_restore_entry(&install_play_service_now_hook)); install_play_service_now_hook.entry=NULL;
    REQUIRE(install_play_service_now((void (*)(void))palette_now));
    for (unsigned i=0;i<2048;++i) *(unsigned char *)(uintptr_t)(0x42c148+i)=(unsigned char)(i*13+i/4);
    palette_table[6]=(uint32_t)(uintptr_t)palette_apply; palette_object=(uint32_t)(uintptr_t)palette_table;
    *(uint32_t *)0x4349b8=(uint32_t)(uintptr_t)&palette_object; *(uint32_t *)0x434998=0;
    spx_observer out=spx_observe_begin(stdout); observer=&out; spx_observe_object(observer,"frame"); snapshot(observer,"initial");
    spx_observe_array(observer,"calls"); ((void (*)(void))0x4044d0)(); play_from_native(); spx_observe_end(observer);
    snapshot(observer,"final"); spx_observe_u64(observer,"palette_calls",palette_calls);
    spx_observe_bytes(observer,"palettes",(void *)0x42c148,2048); spx_observe_end(observer);
    REQUIRE(spx_observe_finish(observer)); fputc('\n',stdout); return 0;
}
static void palette_run_case(void) {
    SetUnhandledExceptionFilter(fault); int argc; char **argv,**environment; struct native_startupinfo startup={0};
    REQUIRE(!__getmainargs(&argc,&argv,&environment,0,&startup)); int result=main(argc,argv); fflush(NULL); ExitProcess((UINT)result);
}
BOOL WINAPI DllMain(HINSTANCE instance,DWORD reason,void *reserved) {
    (void)instance; (void)reserved;
    return reason!=DLL_PROCESS_ATTACH || ((uintptr_t)GetModuleHandleA(NULL)==0x400000 && install_startup(palette_run_case));
}
