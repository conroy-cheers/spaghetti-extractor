/* Equal palette timing inputs at the actual frame's elapsed/now boundary.
 * Other helpers, delay loops and platform clocks keep their existing inputs. */
static DWORD frame_clock_thread;
static uint32_t frame_clock_kind,frame_clock_count,frame_clock_inputs[256][3];
static int frame_clock_caller(uintptr_t caller) { return caller>=0x4044d0 && caller<0x404ac2; }
static int frame_clock_read(uintptr_t caller,uint32_t *value) {
    uint32_t kind=frame_clock_thread==GetCurrentThreadId() ? frame_clock_kind : 0;
    if (!kind && frame_clock_caller(caller)) kind=2;
    if (!kind) return 0;
    REQUIRE(frame_clock_count<256);
    *value=UINT32_C(0xf0000000)+play_frames*16;
    uint32_t *record=frame_clock_inputs[frame_clock_count++];
    record[0]=play_frames; record[1]=kind; record[2]=*value; return 1;
}
static uint32_t frame_clock_elapsed(uint32_t previous,uint32_t delay) {
    DWORD thread=frame_clock_thread; uint32_t kind=frame_clock_kind;
    if (frame_clock_caller((uintptr_t)__builtin_return_address(0))) {
        frame_clock_thread=GetCurrentThreadId(); frame_clock_kind=1;
    }
    REQUIRE(spx_fixture_restore_entry(&install_palette_elapsed_hook));
    uint32_t result=((uint32_t (*)(uint32_t,uint32_t))0x40db80)(previous,delay);
    install_palette_elapsed_hook.entry=NULL;
    REQUIRE(install_palette_elapsed((void (*)(void))frame_clock_elapsed));
    frame_clock_thread=thread; frame_clock_kind=kind; return result;
}
uint32_t play_elapsed(void *user,play_state *s,uint32_t previous,uint32_t delay) {
    REQUIRE(!frame_clock_kind); frame_clock_thread=GetCurrentThreadId(); frame_clock_kind=1;
    uint32_t result=uncontrolled_play_elapsed(user,s,previous,delay);
    frame_clock_thread=0; frame_clock_kind=0; return result;
}
uint32_t play_now(void *user,play_state *s) {
    REQUIRE(!frame_clock_kind); frame_clock_thread=GetCurrentThreadId(); frame_clock_kind=2;
    uint32_t result=uncontrolled_play_now(user,s);
    frame_clock_thread=0; frame_clock_kind=0; return result;
}
static void frame_clock_install(void) {
    play_clock_input=frame_clock_read;
    REQUIRE(install_palette_elapsed((void (*)(void))frame_clock_elapsed));
}
