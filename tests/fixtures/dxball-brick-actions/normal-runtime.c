/* Real services and normal game execution over the established live network. */
#define PLAY_FRAME_CAPACITY 64
#define MOTION_NORMAL_LIBRARY_ONLY 1
#define play_elapsed uncontrolled_play_elapsed
#define play_now uncontrolled_play_now
#include "motion-normal-runtime.c"
#undef play_elapsed
#undef play_now
#include "brick-runtime.h"
#include "palette-inputs.h"
static brick_state bricks={.motion=&motion};
static uint32_t brick_entries[8],brick_depth,brick_count;
static DWORD seed_thread;
static uint32_t seed_input_count,seed_inputs[16];
static uint32_t (WINAPI *seed_parent_clock)(void);
static uint32_t WINAPI seed_clock(void) {
    if (seed_thread && seed_thread==GetCurrentThreadId()) {
        REQUIRE(seed_input_count<16); seed_inputs[seed_input_count++]=1; return 1;
    }
    return seed_parent_clock();
}
static void seed_entry(void) {
    REQUIRE(!seed_thread); seed_thread=GetCurrentThreadId();
    REQUIRE(spx_fixture_restore_entry(&install_brick_seed_hook));
    ((void (*)(void))0x40ae30)(); install_brick_seed_hook.entry=NULL;
    REQUIRE(install_brick_seed(seed_entry)); seed_thread=0;
}
static struct { uint32_t address,seen; brick_effect value; } brick_pool[PLAY_OBJECTS];
static uint32_t brick_objects;
void brick_enter(unsigned operation) { REQUIRE(operation<8); ++brick_entries[operation]; }
static uint32_t brick_id(const brick_effect *p) {
    if (!p) return 0;
    for (uint32_t i=0;i<brick_objects;++i) if (p==&brick_pool[i].value) return i+1;
    REQUIRE(0); return 0;
}
static uint32_t brick_address(brick_effect *p) { uint32_t id=brick_id(p); return id ? brick_pool[id-1].address : 0; }
static brick_effect *brick_view(uint32_t address) {
    if (!address) return NULL;
    uint32_t i;
    for (i=0;i<brick_objects && brick_pool[i].address!=address;++i) {}
    if (i==brick_objects) { REQUIRE(brick_objects<PLAY_OBJECTS); ++brick_objects; brick_pool[i].address=address; }
    brick_effect *view=&brick_pool[i].value;
    if (!brick_pool[i].seen) {
        brick_pool[i].seen=1; const uint32_t *p=word(address); memcpy(view,p,32);
        view->next=brick_view(p[8]); view->previous=brick_view(p[9]);
    }
    return view;
}
static void brick_to_native(void) {
    play.brick_effects.current=effect_view(brick_address(bricks.current));
    play.brick_effects.first=effect_view(brick_address(bricks.first));
    motion_to_native(); *word(0x42cc00)=brick_address(bricks.last); *word(0x42ca54)=bricks.board_index;
    for (uint32_t i=0;i<brick_objects;++i) if (brick_pool[i].seen) {
        uint32_t *p=word(brick_pool[i].address); memcpy(p,&brick_pool[i].value,32);
        p[8]=brick_address(brick_pool[i].value.next); p[9]=brick_address(brick_pool[i].value.previous);
    }
}
static void brick_from_native(void) {
    motion_from_native();
    for (uint32_t i=0;i<brick_objects;++i) brick_pool[i].seen=0;
    bricks.current=brick_view(*word(0x42cbf8)); bricks.first=brick_view(*word(0x42cbfc)); bricks.last=brick_view(*word(0x42cc00));
    bricks.board_index=*word(0x42ca54);
}
uint32_t brick_read_cell(void *u,brick_state *s,uint32_t column,uint32_t row) {
    (void)u;REQUIRE(s==&bricks);brick_to_native();
    uint32_t address=UINT32_C(0x42ca60)+row*20+column;
    return *(const volatile unsigned char *)(uintptr_t)address;
}
void brick_write_cell(void *u,brick_state *s,uint32_t column,uint32_t row,uint32_t value) {
    (void)u;REQUIRE(s==&bricks);brick_to_native();
    uint32_t address=UINT32_C(0x42ca60)+row*20+column;
    *(volatile unsigned char *)(uintptr_t)address=(unsigned char)value;brick_from_native();
}
void brick_write_pending(void *u,brick_state *s,uint32_t column,uint32_t row,uint32_t value) {
    (void)u;REQUIRE(s==&bricks);brick_to_native();
    uint32_t address=UINT32_C(0x42cc10)+row*20+column;
    *(volatile unsigned char *)(uintptr_t)address=(unsigned char)value;brick_from_native();
}
brick_effect *brick_allocate_effect(void *u,brick_state *s) {
    (void)u; REQUIRE(s==&bricks); brick_to_native();
    uint32_t address=((uint32_t (*)(uint32_t))0x40df40)(40); brick_from_native(); if (!address) return NULL;
    uint32_t i;
    for (i=0;i<brick_objects && brick_pool[i].address!=address;++i) {}
    if (i==brick_objects) { REQUIRE(brick_objects<PLAY_OBJECTS); ++brick_objects; brick_pool[i].address=address; }
    REQUIRE(!brick_pool[i].seen); brick_pool[i].seen=1;
    /* Preserve raw allocation bytes, but do not interpret fresh link words. */
    memcpy(&brick_pool[i].value,(void *)(uintptr_t)address,32);
    brick_pool[i].value.next=brick_pool[i].value.previous=NULL; return &brick_pool[i].value;
}
play_event *brick_allocate_event(void *u,brick_state *s) {
    (void)u; REQUIRE(s==&bricks); brick_to_native();
    uint32_t address=((uint32_t (*)(uint32_t))0x40df40)(20); brick_from_native(); if (!address) return NULL;
    uint32_t i;
    for (i=0;i<event_count && event_pool[i].address!=address;++i) {}
    if (i==event_count) { REQUIRE(event_count<PLAY_OBJECTS); ++event_count; event_pool[i].address=address; }
    REQUIRE(!event_pool[i].seen); event_pool[i].seen=1;
    memcpy(&event_pool[i].value,(void *)(uintptr_t)address,12);
    event_pool[i].value.next=event_pool[i].value.previous=NULL; return &event_pool[i].value;
}
void brick_free_effect(void *u,brick_state *s,brick_effect *effect) {
    (void)u; REQUIRE(s==&bricks); uint32_t address=brick_address(effect); brick_to_native();
    ((void (*)(uint32_t))0x40df30)(address); brick_from_native();
}
#define BRICK_VOID1(name,address) \
void brick_##name(void *u,brick_state *s,uint32_t value) { (void)u; REQUIRE(s==&bricks); brick_to_native(); ((void (*)(uint32_t))address)(value); brick_from_native(); }
BRICK_VOID1(select_board,0x403ed0) BRICK_VOID1(stop_sound,0x403370)
#undef BRICK_VOID1
#define BRICK_RESULT1(name,address) \
uint32_t brick_##name(void *u,brick_state *s,uint32_t value) { (void)u; REQUIRE(s==&bricks); brick_to_native(); uint32_t result=((uint32_t (*)(uint32_t))address)(value); brick_from_native(); return result; }
BRICK_RESULT1(pan,0x403550) BRICK_RESULT1(random,0x40ae20)
#undef BRICK_RESULT1
#define BRICK_VOID3(name,address) \
void brick_##name(void *u,brick_state *s,uint32_t a,uint32_t b,uint32_t c) { (void)u; REQUIRE(s==&bricks); brick_to_native(); ((void (*)(uint32_t,uint32_t,uint32_t))address)(a,b,c); brick_from_native(); }
BRICK_VOID3(cell,0x405ad0) BRICK_VOID3(sprite_fast,0x401140) BRICK_VOID3(sprite_opaque,0x40bdd0) BRICK_VOID3(sprite_transparent,0x40bd90)
#undef BRICK_VOID3
#define BRICK_VOID4(name,address) \
void brick_##name(void *u,brick_state *s,uint32_t a,uint32_t b,uint32_t c,uint32_t d) { (void)u; REQUIRE(s==&bricks); brick_to_native(); ((void (*)(uint32_t,uint32_t,uint32_t,uint32_t))address)(a,b,c,d); brick_from_native(); }
BRICK_VOID4(play_sound,0x403210) BRICK_VOID4(debris,0x406ef0)
#undef BRICK_VOID4
void brick_particle(void *u,brick_state *s,uint32_t a,uint32_t b,uint32_t c,uint32_t d,uint32_t e,uint32_t f) {
    (void)u; REQUIRE(s==&bricks); brick_to_native(); ((void (*)(uint32_t,uint32_t,uint32_t,uint32_t,uint32_t,uint32_t))0x407b00)(a,b,c,d,e,f); brick_from_native();
}
void brick_destination(void *u,brick_state *s,font_surface *surface) {
    (void)u; REQUIRE(s==&bricks); brick_to_native(); ((void (*)(uint32_t))0x40bd60)(surface_address(surface)); brick_from_native();
}
void brick_erase(void *u,brick_state *s,font_rect *rectangle) {
    (void)u; REQUIRE(s==&bricks); brick_to_native(); ((void (*)(font_rect))0x401280)(*rectangle); brick_from_native();
}
void brick_blit_fast(void *u,brick_state *s,font_surface *destination,uint32_t x,uint32_t y,font_surface *source,font_rect *rectangle,uint32_t flags) {
    (void)u; REQUIRE(s==&bricks); brick_to_native(); uint32_t address=surface_address(destination),*table=word(*word(address));
    ((uint32_t (WINAPI *)(uint32_t,uint32_t,uint32_t,uint32_t,font_rect *,uint32_t))(uintptr_t)table[7])(address,x,y,surface_address(source),rectangle,flags); brick_from_native();
}
typedef struct {
    uint32_t operation,args[4],result,fields[9],roots[6],effects[PLAY_OBJECTS][11],effects_size;
    unsigned char board[400],pending[400];
} brick_snapshot;
static brick_snapshot brick_records[128];
static void brick_record(uint32_t operation,uint32_t a,uint32_t b,uint32_t c,uint32_t d,uint32_t result) {
    if (--brick_depth) return;
    REQUIRE(brick_count<128); brick_from_native(); brick_snapshot *r=&brick_records[brick_count++];
    r->operation=operation; r->args[0]=a; r->args[1]=b; r->args[2]=c; r->args[3]=d; r->result=result;
    uint32_t fields[]={play.remaining_bricks,play.voice_pending,menu.score,title.fast,motion.pierce,motion.impact_dx,motion.impact_dy,bricks.board_index,*word(0x417c74)};
    memcpy(r->fields,fields,sizeof(fields));
    uint32_t roots[]={brick_id(bricks.current),brick_id(bricks.first),brick_id(bricks.last),event_id(play.events.current),event_id(play.events.first),event_id(play.events.last)};
    memcpy(r->roots,roots,sizeof(roots));
    for (uint32_t i=0;i<brick_objects;++i) if (brick_pool[i].seen) {
        const brick_effect *e=&brick_pool[i].value;
        /* Uninitialized allocation bytes are preserved but are not evaluated as
         * deterministic outputs. The local initialized-byte cases check them. */
        uint32_t words[]={i+1,e->kind,e->sprite,e->x,e->y,e->kind==2 ? e->tile : 0,e->frames,e->delay,e->tick,brick_id(e->next),brick_id(e->previous)};
        memcpy(r->effects[r->effects_size++],words,sizeof(words));
    }
    memcpy(r->board,motion.board,400); memcpy(r->pending,play.pending_cells,400);
}
#define BRICK_LIVE0(name,op,address) \
static void live_brick_##name(void) { ++brick_depth; brick_from_native(); \
    if (source_side) { fixture_brick_##name(&bricks); brick_to_native(); } \
    else { REQUIRE(spx_fixture_restore_entry(&install_brick_##name##_hook)); ((void (*)(void))address)(); \
        install_brick_##name##_hook.entry=NULL; REQUIRE(install_brick_##name(live_brick_##name)); } \
    brick_record(op,0,0,0,0,0); }
BRICK_LIVE0(reset,0,0x405a70) BRICK_LIVE0(advance,2,0x406020) BRICK_LIVE0(step_blast,4,0x406140) BRICK_LIVE0(step_flash,7,0x4065e0)
#undef BRICK_LIVE0
#define BRICK_LIVE2(name,op,address) \
static void live_brick_##name(uint32_t a,uint32_t b) { ++brick_depth; brick_from_native(); \
    if (source_side) { fixture_brick_##name(&bricks,a,b); brick_to_native(); } \
    else { REQUIRE(spx_fixture_restore_entry(&install_brick_##name##_hook)); ((void (*)(uint32_t,uint32_t))address)(a,b); \
        install_brick_##name##_hook.entry=NULL; REQUIRE(install_brick_##name((void (*)(void))live_brick_##name)); } \
    brick_record(op,a,b,0,0,0); }
BRICK_LIVE2(blast,3,0x406070) BRICK_LIVE2(queue,5,0x406410)
#undef BRICK_LIVE2
static uint32_t live_brick_hit(uint32_t a,uint32_t b) {
    ++brick_depth; brick_from_native(); uint32_t result;
    if (source_side) { result=fixture_brick_hit(&bricks,a,b); brick_to_native(); }
    else { REQUIRE(spx_fixture_restore_entry(&install_brick_hit_hook)); result=((uint32_t (*)(uint32_t,uint32_t))0x405c80)(a,b);
        install_brick_hit_hook.entry=NULL; REQUIRE(install_brick_hit((void (*)(void))live_brick_hit)); }
    brick_record(1,a,b,0,0,result); return result;
}
static void live_brick_flash(uint32_t a,uint32_t b,uint32_t c,uint32_t d) {
    ++brick_depth; brick_from_native();
    if (source_side) { fixture_brick_flash(&bricks,a,b,c,d); brick_to_native(); }
    else { REQUIRE(spx_fixture_restore_entry(&install_brick_flash_hook)); ((void (*)(uint32_t,uint32_t,uint32_t,uint32_t))0x4064b0)(a,b,c,d);
        install_brick_flash_hook.entry=NULL; REQUIRE(install_brick_flash((void (*)(void))live_brick_flash)); }
    brick_record(6,a,b,c&255,d,0);
}
static void brick_observe(spx_observer *observer) {
    spx_observer o=*observer; motion_observe(&o); spx_observe_array(&o,"bricks");
    for (uint32_t i=0;i<brick_count;++i) {
        brick_snapshot *r=&brick_records[i]; spx_observe_object(&o,NULL);
        spx_observe_u64(&o,"operation",r->operation); spx_observe_u32s(&o,"arguments",r->args,4); spx_observe_u64(&o,"result",r->result);
        spx_observe_u32s(&o,"fields",r->fields,9); spx_observe_u32s(&o,"roots",r->roots,6); spx_observe_array(&o,"effects");
        for (uint32_t j=0;j<r->effects_size;++j) spx_observe_u32s(&o,NULL,r->effects[j],11);
        spx_observe_end(&o); spx_observe_bytes(&o,"board",r->board,400); spx_observe_bytes(&o,"pending",r->pending,400); spx_observe_end(&o);
    }
    spx_observe_end(&o); spx_observe_u32s(&o,"random_seed_inputs",seed_inputs,seed_input_count);
    spx_observe_array(&o,"palette_clock_inputs");
    for (uint32_t i=0;i<frame_clock_count;++i) spx_observe_u32s(&o,NULL,frame_clock_inputs[i],3);
    spx_observe_end(&o);
    *observer=o;
}
static void brick_diagnose(spx_observer *observer) {
    motion_diagnose(observer); spx_observe_u32s(observer,"selected_bricks",brick_entries,8);
}
static void brick_report(void) {
    const char *path=getenv("SPX_COMPARISON_REPORT"); if (!path) return; FILE *out=fopen(path,"wb"); REQUIRE(out);
    fprintf(out,"{\"side\":\"%s\",\"exit_code\":0,\"observations\":",source_side ? "source" : "original");
    spx_observer o=spx_observe_begin(out); brick_observe(&o);
    REQUIRE(spx_observe_finish(&o)); fputs(",\"diagnostics\":",out); o=spx_observe_begin(out);
    brick_diagnose(&o);
    REQUIRE(spx_observe_finish(&o)); fputs("}\n",out); fclose(out);
}
static BOOL brick_main(HINSTANCE instance,DWORD reason,void *reserved) {
    if (!motion_main(instance,reason,reserved)) return FALSE;
    if (reason==DLL_PROCESS_DETACH) { brick_report(); return TRUE; }
    if (reason!=DLL_PROCESS_ATTACH) return TRUE;
#define BRICK_ENTRY(name) REQUIRE(install_brick_##name((void (*)(void))live_brick_##name));
    BRICK_ENTRY(reset) BRICK_ENTRY(hit) BRICK_ENTRY(advance) BRICK_ENTRY(blast)
    BRICK_ENTRY(step_blast) BRICK_ENTRY(queue) BRICK_ENTRY(flash) BRICK_ENTRY(step_flash)
#undef BRICK_ENTRY
    seed_parent_clock=(uint32_t (WINAPI *)(void))(uintptr_t)*word(0x415174);
    DWORD old,ignored; REQUIRE(VirtualProtect((void *)0x415174,4,PAGE_READWRITE,&old));
    *word(0x415174)=(uint32_t)(uintptr_t)seed_clock;
    REQUIRE(VirtualProtect((void *)0x415174,4,old,&ignored)); REQUIRE(install_brick_seed(seed_entry));
    frame_clock_install();
    return TRUE;
}
#ifndef BRICK_NORMAL_LIBRARY_ONLY
BOOL WINAPI DllMain(HINSTANCE instance,DWORD reason,void *reserved) { return brick_main(instance,reason,reserved); }
#endif
