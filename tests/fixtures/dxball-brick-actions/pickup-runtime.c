/* Reduce the real collision's random pickup outcome without running the game. */
#define main controlled_brick_main
#define DllMain controlled_brick_dll_main
#define brick_debris controlled_brick_debris
#include "brick-local-runtime.c"
#undef main
#undef DllMain
#undef brick_debris

static uint32_t pickup_records[4][9],pickup_count,pickup_random_calls;
static uint32_t pickup_allocate(uint32_t bytes) {
    if (bytes!=36) return native_allocate(bytes);
    brick_from_native(); begin(&bricks,250,&bytes,1); REQUIRE(pickup_count<4);
    uint32_t *record=pickup_records[pickup_count++]; memset(record,0xa5,36); (void)end(pickup_count);
    brick_to_native(); return (uint32_t)(uintptr_t)record;
}
static uint32_t pickup_random(uint32_t limit) {
    brick_from_native(); begin(&bricks,BRICK_RANDOM,&limit,1); REQUIRE(limit && limit<0x80000000);
    uint32_t result=((uint32_t (*)(void))0x40ea70)()%limit; ++pickup_random_calls;
    (void)end(result); brick_to_native(); return result;
}
void brick_debris(void *u,brick_state *s,uint32_t column,uint32_t row,uint32_t dx,uint32_t dy) {
    (void)u; REQUIRE(s==&bricks); brick_to_native();
    ((void (*)(uint32_t,uint32_t,uint32_t,uint32_t))0x406ef0)(column,row,dx,dy); brick_from_native();
}
static uint32_t pickup_id(uint32_t address) {
    if (!address) return 0;
    for (unsigned i=0;i<pickup_count;++i) if (address==(uint32_t)(uintptr_t)pickup_records[i]) return i+1;
    REQUIRE(0); return 0;
}
int main(int argc,char **argv) {
    REQUIRE(argc==3); scenario=(uint32_t)strtoul(argv[2],NULL,10); REQUIRE(scenario>=100 && scenario<104);
    int source=!strcmp(argv[1],"source"); setup(); install(source);
    REQUIRE(spx_fixture_restore_entry(&install_brick_service_debris_hook));
    REQUIRE(spx_fixture_restore_entry(&install_brick_service_allocate_hook)); install_brick_service_allocate_hook.entry=NULL;
    REQUIRE(install_brick_service_allocate((void (*)(void))pickup_allocate));
    REQUIRE(spx_fixture_restore_entry(&install_brick_service_random_hook)); install_brick_service_random_hook.entry=NULL;
    REQUIRE(install_brick_service_random((void (*)(void))pickup_random));
    title.fast=scenario<102; current_board.cells[12][18]=14; motion.impact_dx=1; motion.impact_dy=0xfffffffe;
    play.remaining_bricks=168; menu.score=0;
    uint32_t chosen_seed=1+(scenario%2);
#ifdef PICKUP_UNEQUAL_INPUT
    if (source) ++chosen_seed;
#endif
    ((void (*)(uint32_t))0x40ea60)(chosen_seed);
    *play_word(0x431cb8)=0; *play_word(0x431c50)=*play_word(0x431c54)=*play_word(0x431c58)=0;
    brick_to_native(); spx_observer out=spx_observe_begin(stdout); observer=&out;
    spx_observe_object(observer,"bricks"); snapshot("initial"); spx_observe_array(observer,"calls");
    uint32_t result=HIT(18,12); brick_from_native(); spx_observe_end(observer); snapshot("final");
    spx_observe_u64(observer,"result",result); spx_observe_u64(observer,"random_calls",pickup_random_calls);
    uint32_t roots[]={*play_word(0x431cb8),pickup_id(*play_word(0x431c50)),pickup_id(*play_word(0x431c54)),pickup_id(*play_word(0x431c58))};
    spx_observe_u32s(observer,"pickups",roots,4); spx_observe_array(observer,"pickup_records");
    for (unsigned i=0;i<pickup_count;++i) {
        uint32_t row[9]; memcpy(row,pickup_records[i],28); row[7]=pickup_id(pickup_records[i][7]); row[8]=pickup_id(pickup_records[i][8]);
        spx_observe_u32s(observer,NULL,row,9);
    }
    spx_observe_end(observer); spx_observe_end(observer); REQUIRE(spx_observe_finish(observer)); fputc('\n',stdout); return 0;
}
static void pickup_run_case(void) {
    SetUnhandledExceptionFilter(fault); int argc; char **argv,**environment; struct native_startupinfo startup={0};
    REQUIRE(!__getmainargs(&argc,&argv,&environment,0,&startup)); int result=main(argc,argv); fflush(NULL); ExitProcess((UINT)result);
}
BOOL WINAPI DllMain(HINSTANCE instance,DWORD reason,void *reserved) {
    (void)instance; (void)reserved;
    return reason!=DLL_PROCESS_ATTACH || ((uintptr_t)GetModuleHandleA(NULL)==0x400000 && install_startup(pickup_run_case));
}
