/* Identical explicit environment inputs for the retained native paddle helper.
 * Other calls keep the actual platform clock and native random implementation. */
static DWORD paddle_input_thread;
static uint32_t paddle_input_tick,paddle_input_count,paddle_inputs[256][4];
static uint32_t (WINAPI *paddle_platform_clock)(void);
/* An enclosing consumer may supply other explicitly scoped clock inputs. */
static int (*play_clock_input)(uintptr_t caller,uint32_t *value);
static int paddle_input_active(void) {
    return paddle_input_thread && paddle_input_thread==GetCurrentThreadId();
}
static uint32_t paddle_input(unsigned kind,uint32_t argument,uint32_t result) {
    REQUIRE(paddle_input_count<256);
    uint32_t *row=paddle_inputs[paddle_input_count++];
    row[0]=play_frames; row[1]=kind; row[2]=argument; row[3]=result; return result;
}
static uint32_t WINAPI paddle_input_clock(void) {
    return paddle_input_active() ? paddle_input(0,0,paddle_input_tick) : paddle_platform_clock();
}
static uint32_t paddle_input_now(void) {
    if (paddle_input_active()) return paddle_input(1,0,paddle_input_tick);
    uint32_t value;
    if (play_clock_input && play_clock_input((uintptr_t)__builtin_return_address(0),&value)) return value;
    REQUIRE(spx_fixture_restore_entry(&install_paddle_input_now_hook));
    uint32_t result=((uint32_t (*)(void))0x40db20)();
    install_paddle_input_now_hook.entry=NULL;
    REQUIRE(install_paddle_input_now((void (*)(void))paddle_input_now)); return result;
}
static uint32_t paddle_input_random(uint32_t limit) {
    if (paddle_input_active()) { REQUIRE(limit); return paddle_input(2,limit,play_frames%limit); }
    REQUIRE(spx_fixture_restore_entry(&install_paddle_input_random_hook));
    uint32_t result=((uint32_t (*)(uint32_t))0x40ae20)(limit);
    install_paddle_input_random_hook.entry=NULL;
    REQUIRE(install_paddle_input_random((void (*)(void))paddle_input_random)); return result;
}
static void paddle_input_draw(void) {
    REQUIRE(!paddle_input_thread);
    paddle_input_tick=UINT32_C(0xf0000000)+play_frames*64;
    /* The first call advances beyond the initial animation deadlines. Subsequent
     * calls use the same domain; no gameplay state is overwritten to force it. */
    REQUIRE(*word(0x431c70)<paddle_input_tick && *word(0x42ca50)<paddle_input_tick);
    paddle_input_thread=GetCurrentThreadId();
    REQUIRE(spx_fixture_restore_entry(&install_paddle_input_draw_hook));
    ((void (*)(void))0x4067b0)();
    install_paddle_input_draw_hook.entry=NULL;
    REQUIRE(install_paddle_input_draw(paddle_input_draw)); paddle_input_thread=0;
}
static void paddle_inputs_install(void) {
    paddle_platform_clock=(uint32_t (WINAPI *)(void))(uintptr_t)*word(0x415174);
    DWORD old,ignored; REQUIRE(VirtualProtect((void *)0x415174,4,PAGE_READWRITE,&old));
    *word(0x415174)=(uint32_t)(uintptr_t)paddle_input_clock;
    REQUIRE(VirtualProtect((void *)0x415174,4,old,&ignored));
    REQUIRE(install_paddle_input_now((void (*)(void))paddle_input_now));
    REQUIRE(install_paddle_input_random((void (*)(void))paddle_input_random));
    REQUIRE(install_paddle_input_draw(paddle_input_draw));
}
