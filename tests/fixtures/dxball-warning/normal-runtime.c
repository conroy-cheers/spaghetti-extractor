/* Native platform backend; keep historical words separate from host stack bytes. */
#define GAME_NORMAL_LIBRARY_ONLY 1
#define paddle_sprite warning_parent_paddle_sprite
#define play_sprite warning_parent_play_sprite
#define pickup_sprite warning_parent_pickup_sprite
#define particle_describe warning_parent_particle_describe
#define particle_lock warning_parent_particle_lock
#define particle_unlock warning_parent_particle_unlock
#include "game-normal-runtime.c"
#undef particle_unlock
#undef particle_lock
#undef particle_describe
#undef pickup_sprite
#undef play_sprite
#undef paddle_sprite
#include "warning-runtime.h"
#include "history.h"
static warning_state warning={.progression=&progress};
static warning_frame_history warning_history;
static uint32_t warning_history_ready,warning_entries[2],warning_count;
uint32_t warning_native_input[3] __attribute__((used));
static void warning_register_context(void) {
    /* Reviewed WinMain -> flow frame -> gameplay frame path; these are logical
     * values in this original environment, not portable function pointers. */
    warning_history.incoming_ebp=*word(0x415148);
    warning_history.incoming_esi=*word(0x415164);
}
void paddle_sprite(void *u,paddle_state *s,uint32_t slot,uint32_t x,uint32_t y) {
    REQUIRE(s==&paddle);warning_register_context();
    warning_history_paddle(&warning_history,slot,play.paddle_y-y);warning_history_ready=1;
    warning_parent_paddle_sprite(u,s,slot,x,y);
}
void play_sprite(void *u,play_state *s,uint32_t slot,uint32_t x,uint32_t y) {
    REQUIRE(s==&play);warning_register_context();warning_history_frame_sprite(&warning_history);
    warning_parent_play_sprite(u,s,slot,x,y);
}
void pickup_sprite(void *u,pickup_state *s,uint32_t slot,uint32_t x,uint32_t y) {
    REQUIRE(s==&pickups);warning_register_context();warning_history_pickup_sprite(&warning_history);
    warning_parent_pickup_sprite(u,s,slot,x,y);
}
static struct pcx_native_lease *warning_descriptor(pcx_view *view) {
    struct pcx_native_lease *lease=pcx_leases;
    while (lease && lease->view!=view) lease=lease->next;
    REQUIRE(lease);return lease;
}
void particle_describe(void *u,particle_state *s,font_surface *surface,pcx_view *view) {
    (void)u;REQUIRE(s==&particles && warning_history_ready);particle_to_native();
    struct pcx_native_lease *lease=calloc(1,sizeof(*lease));REQUIRE(lease);
    lease->view=view;lease->surface=surface;lease->desc[0]=108;lease->desc[1]=14;
    warning_history_to_descriptor(&warning_history,lease->desc);
    uint32_t address=surface_address(surface),*table=word(*word(address));
    ((uint32_t (WINAPI *)(uint32_t,void *))(uintptr_t)table[22])(address,lease->desc);
    warning_history_from_descriptor(&warning_history,lease->desc);
    view->width=lease->desc[3];view->height=lease->desc[2];view->image.pitch=lease->desc[4];view->image.pixels=NULL;
    lease->next=pcx_leases;pcx_leases=lease;particle_from_native();
}
uint32_t particle_lock(void *u,particle_state *s,font_surface *surface,pcx_view *view) {
    uint32_t result=warning_parent_particle_lock(u,s,surface,view);
    warning_history_from_descriptor(&warning_history,warning_descriptor(view)->desc);return result;
}
void particle_unlock(void *u,particle_state *s,font_surface *surface) {
    (void)u;REQUIRE(s==&particles);particle_to_native();struct pcx_native_lease **link=&pcx_leases;
    while (*link && (*link)->surface!=surface) link=&(*link)->next;
    REQUIRE(*link);struct pcx_native_lease *lease=*link;
    uint32_t address=surface_address(surface),*table=word(*word(address));
    ((uint32_t (WINAPI *)(uint32_t,void *))(uintptr_t)table[32])(address,NULL);
    warning_history_from_descriptor(&warning_history,lease->desc);*link=lease->next;free(lease);particle_from_native();
}
void warning_enter(unsigned op) { REQUIRE(op<2);++warning_entries[op]; }
static void warning_from_native(void) {
    game_from_native();warning.x=*word(0x42cdb0);memcpy(&warning.rectangle,(void *)0x42cda0,16);
}
static void warning_to_native(void) {
    game_to_native();*word(0x42cdb0)=warning.x;memcpy((void *)0x42cda0,&warning.rectangle,16);
}
#define WARNING_BEGIN() (void)u;REQUIRE(s==&warning);warning_to_native()
#define WARNING_END() warning_from_native()
uint32_t warning_now(void *u,warning_state *s) {
    WARNING_BEGIN();uint32_t value=((uint32_t (WINAPI *)(void))(uintptr_t)*word(0x415174))();WARNING_END();return value;
}
uint32_t warning_random(void *u,warning_state *s,uint32_t limit) {
    WARNING_BEGIN();uint32_t value=((uint32_t (*)(uint32_t))0x40ae20)(limit);WARNING_END();return value;
}
#define WARN1(name,address) void warning_##name(void *u,warning_state *s,uint32_t a) { WARNING_BEGIN();((void (*)(uint32_t))address)(a);WARNING_END(); }
WARN1(stop_sound,0x403370) WARN1(select_bank,0x40bd70)
#undef WARN1
#define WARN2(name,address) void warning_##name(void *u,warning_state *s,uint32_t a,uint32_t b) { WARNING_BEGIN();((void (*)(uint32_t,uint32_t))address)(a,b);WARNING_END(); }
WARN2(queue,0x406410) WARN2(explosion,0x406d30)
#undef WARN2
#define WARN4(name,address) void warning_##name(void *u,warning_state *s,uint32_t a,uint32_t b,uint32_t c,uint32_t d) { WARNING_BEGIN();((void (*)(uint32_t,uint32_t,uint32_t,uint32_t))address)(a,b,c,d);WARNING_END(); }
WARN4(play_sound,0x403210) WARN4(loop_sound,0x4032b0)
#undef WARN4
void warning_particle(void *u,warning_state *s,uint32_t a,uint32_t b,uint32_t c,uint32_t d,uint32_t e,uint32_t f) {
    WARNING_BEGIN();((void (*)(uint32_t,uint32_t,uint32_t,uint32_t,uint32_t,uint32_t))0x407b00)(a,b,c,d,e,f);WARNING_END();
}
void warning_blit_fast(void *u,warning_state *s,font_surface *destination,uint32_t x,uint32_t y,font_surface *source,font_rect *bounds,uint32_t flags) {
    WARNING_BEGIN();REQUIRE(bounds==&warning.rectangle);uint32_t address=surface_address(destination),*table=word(*word(address));
    ((uint32_t (WINAPI *)(uint32_t,uint32_t,uint32_t,uint32_t,void *,uint32_t))(uintptr_t)table[7])
        (address,x,y,surface_address(source),(void *)0x42cda0,flags);WARNING_END();
}
void warning_damage(void *u,warning_state *s,font_rect *bounds) {
    WARNING_BEGIN();((void (*)(font_rect))0x401200)(*bounds);WARNING_END();
}
#undef WARNING_BEGIN
#undef WARNING_END
static uint32_t warning_records[256][12];
static void warning_record(unsigned operation) {
    REQUIRE(warning_count<256);warning_from_native();uint32_t values[]={operation,warning.x,progress.warning_y,
        progress.warning_frames,play.warning_sound,warning.rectangle.left,warning.rectangle.top,warning.rectangle.right,
        warning.rectangle.bottom,title.font->objects->current_bank,observed_surface(surface_address(title.software)),play.remaining_bricks};
    memcpy(warning_records[warning_count++],values,sizeof(values));
}
/* Capture native entry words before a C wrapper changes the stack, and supply
 * those same words to the original body when checking the instrumented side. */
static void __attribute__((naked)) warning_original_prepare(void) {
    __asm__ volatile("movl _warning_native_input, %eax\n\tmovl %eax, -28(%esp)\n\t"
        "movl _warning_native_input+4, %eax\n\tmovl %eax, -24(%esp)\n\t"
        "movl _warning_native_input+8, %eax\n\tmovl %eax, -20(%esp)\n\t"
        "movl $0x408c20, %eax\n\tjmp *%eax\n\t");
}
static void live_warning_prepare(void);
static void __attribute__((used,noinline)) warning_prepare_body(void) {
    warning_from_native();
    if (source_side) {
        REQUIRE(warning_history_ready);warning.fallback=warning_history.words;fixture_warning_prepare(&warning);warning_to_native();
    } else {
        REQUIRE(spx_fixture_restore_entry(&install_warning_prepare_hook));warning_original_prepare();
        install_warning_prepare_hook.entry=NULL;REQUIRE(install_warning_prepare(live_warning_prepare));
    }
    warning_record(0);
}
static void __attribute__((naked)) live_warning_prepare(void) {
    __asm__ volatile("movl -28(%esp), %eax\n\tmovl %eax, _warning_native_input\n\t"
        "movl -24(%esp), %eax\n\tmovl %eax, _warning_native_input+4\n\t"
        "movl -20(%esp), %eax\n\tmovl %eax, _warning_native_input+8\n\t"
        "jmp _warning_prepare_body\n\t");
}
static void live_warning_draw(void) {
    warning_from_native();
    if (source_side) { fixture_warning_draw(&warning);warning_to_native(); }
    else { REQUIRE(spx_fixture_restore_entry(&install_warning_draw_hook));((void (*)(void))0x408ed0)();
        install_warning_draw_hook.entry=NULL;REQUIRE(install_warning_draw(live_warning_draw)); }
    warning_record(1);
}
static void warning_observe(spx_observer *o) {
    game_observe(o);spx_observe_array(o,"warning");
    for (uint32_t i=0;i<warning_count;++i) spx_observe_u32s(o,NULL,warning_records[i],12);
    spx_observe_end(o);
}
static void warning_diagnose(spx_observer *o) {
    game_diagnose(o);spx_observe_u32s(o,"selected_warning",warning_entries,2);
}
static void warning_report(void) {
    const char *path=getenv("SPX_COMPARISON_REPORT");if (!path) return;FILE *out=fopen(path,"wb");REQUIRE(out);
    fprintf(out,"{\"side\":\"%s\",\"exit_code\":0,\"observations\":",source_side ? "source" : "original");
    spx_observer o=spx_observe_begin(out);warning_observe(&o);
    REQUIRE(spx_observe_finish(&o));fputs(",\"diagnostics\":",out);o=spx_observe_begin(out);
    warning_diagnose(&o);
    REQUIRE(spx_observe_finish(&o));fputs("}\n",out);fclose(out);
}
static BOOL warning_main(HINSTANCE instance,DWORD reason,void *reserved) {
    if (!game_main(instance,reason,reserved)) return FALSE;
    if (reason==DLL_PROCESS_DETACH) { warning_report();return TRUE; }
    if (reason!=DLL_PROCESS_ATTACH) return TRUE;
    REQUIRE(install_warning_prepare(live_warning_prepare));REQUIRE(install_warning_draw(live_warning_draw));return TRUE;
}
#ifndef WARNING_NORMAL_LIBRARY_ONLY
BOOL WINAPI DllMain(HINSTANCE instance,DWORD reason,void *reserved) { return warning_main(instance,reason,reserved); }
#endif
