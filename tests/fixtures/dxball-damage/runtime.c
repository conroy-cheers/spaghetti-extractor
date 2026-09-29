/* A local consumer: the original machine entries run without a window or UI. */
#define SCENE_LIBRARY_ONLY 1
#include "scene-runtime.c"
#include "damage-runtime.h"

static damage_state damage;
static uint32_t damage_mode, damage_stage, damage_callbacks[6], damage_entries[13];
static uint32_t damage_calls[4096][16], damage_call_count, damage_clock, flip_calls;
static const uint32_t damage_guard_addresses[]={0x41a7e4,0x41c72c,0x42c144};
static uint32_t damage_guards[]={0xfedcba98,0x12345678,0xa5511223};
void damage_enter(unsigned operation) { REQUIRE(operation<13); ++damage_entries[operation]; }
#define DAMAGE_RECORD(...) do { const uint32_t values[]={__VA_ARGS__}; \
    REQUIRE(damage_call_count<4096 && sizeof(values)<=sizeof(damage_calls[0])); \
    memcpy(damage_calls[damage_call_count++],values,sizeof(values)); } while (0)

static uint32_t rectangle_identity(const font_rect *r) {
    uintptr_t pointer=(uintptr_t)r, history=(uintptr_t)damage.history, pending=(uintptr_t)damage.pending;
    if (pointer>=history && pointer<history+sizeof(damage.history)) return 1000+(uint32_t)((pointer-history)/sizeof(*r));
    if (pointer>=pending && pointer<pending+sizeof(damage.pending)) return 4000+(uint32_t)((pointer-pending)/sizeof(*r));
    return 0;
}
static void damage_callback(font_rect *rectangle,font_sprite *object) {
    if (damage_callbacks[damage_stage]++) return;
    if (damage_mode==6 && damage_stage==1) {
        REQUIRE(object); put_word(object,8,37); put_word(object,12,43);
        rectangle->right+=1; damage.page=1; title.fast=0;
    } else if (damage_mode==7 && damage_stage==2) {
        rectangle->right-=1; damage.page=1; damage.count[1]=3; title.fast=1;
        damage.history[0][1]=(font_rect){31,33,45,49};
        damage.history[1][1]=(font_rect){61,63,75,79};
        damage.history[2][1]=(font_rect){91,93,105,109};
        title.software=&surfaces[3]; damage.background=&surfaces[0];
        damage.clipped^=1; /* Branch choice was captured at operation entry. */
    } else if (damage_mode==8 && damage_stage==3) {
        REQUIRE(rectangle_identity(rectangle)==0); rectangle->right-=2; rectangle->bottom-=3;
        scene.presentation_mode=0; damage.capability=2; title.fast=0; damage.page=1;
    } else if (damage_mode==9 && damage_stage==4) {
        rectangle->bottom-=1; damage.pending[damage.pending_count++]=(font_rect){211,213,223,225};
        title.primary=&surfaces[0]; scene.flip=&surfaces[3]; damage.clipped^=1;
    }
}
static int valid_rectangle(const font_rect *rectangle) {
    return rectangle->left<=rectangle->right && rectangle->right<=640
        && rectangle->top<=rectangle->bottom && rectangle->bottom<=480;
}
static void copy_pixels(font_surface *destination,uint32_t x,uint32_t y,font_surface *source,
                        const font_rect *rectangle,uint32_t flags) {
    if (!valid_rectangle(rectangle)) return;
    uint32_t width=rectangle->right-rectangle->left, height=rectangle->bottom-rectangle->top;
    if (x>640-width || y>480-height) return;
    for (uint32_t line=0;line<height;++line) {
        unsigned char *out=scene_pixels(destination)+(y+line)*640+x;
        const unsigned char *in=scene_pixels(source)+(rectangle->top+line)*640+rectangle->left;
        if (flags!=0x11) memmove(out,in,width);
        else for (uint32_t column=0;column<width;++column) if (in[column]) out[column]=in[column];
    }
}
static void damage_fast(font_surface *destination,uint32_t x,uint32_t y,font_surface *source,
                        font_rect *rectangle,uint32_t flags,uint32_t identity,font_sprite *object) {
    DAMAGE_RECORD(0,surface_id(destination),x,y,surface_id(source),rectangle->left,rectangle->top,
        rectangle->right,rectangle->bottom,flags,identity,damage.page,title.fast,damage_stage);
    copy_pixels(destination,x,y,source,rectangle,flags); damage_callback(rectangle,object);
}
void damage_sprite_blit(void *unused,damage_state *s,font_surface *destination,font_sprite *object,
                         uint32_t x,uint32_t y,uint32_t flags) {
    (void)unused; REQUIRE(s==&damage);
    font_rect rectangle={font_word(object,20),font_word(object,24),font_word(object,28),font_word(object,32)};
    damage_fast(destination,x,y,object->surface,&rectangle,flags,6000+sprite_id(object),object);
    put_word(object,20,rectangle.left); put_word(object,24,rectangle.top);
    put_word(object,28,rectangle.right); put_word(object,32,rectangle.bottom);
}
void damage_blit_fast(void *unused,damage_state *s,font_surface *destination,uint32_t x,uint32_t y,
                      font_surface *source,font_rect *rectangle,uint32_t flags) {
    (void)unused; REQUIRE(s==&damage);
    damage_fast(destination,x,y,source,rectangle,flags,rectangle_identity(rectangle),NULL);
}
void damage_blit(void *unused,damage_state *s,font_surface *destination,font_rect *dr,
                 font_surface *source,font_rect *sr,uint32_t flags) {
    (void)unused; REQUIRE(s==&damage && flags==0x01000000);
    DAMAGE_RECORD(1,surface_id(destination),dr->left,dr->top,dr->right,dr->bottom,
        surface_id(source),sr->left,sr->top,sr->right,sr->bottom,flags,dr==sr,rectangle_identity(dr),damage_stage);
    if (valid_rectangle(dr) && dr->right-dr->left==sr->right-sr->left && dr->bottom-dr->top==sr->bottom-sr->top)
        copy_pixels(destination,dr->left,dr->top,source,sr,0x10);
    damage_callback(dr,NULL);
}
uint32_t damage_now(void *unused,damage_state *s) {
    (void)unused; REQUIRE(s==&damage); damage_clock+=13; DAMAGE_RECORD(2,damage_clock); return damage_clock;
}
uint32_t damage_elapsed(void *unused,damage_state *s,uint32_t previous,uint32_t delay) {
    (void)unused; REQUIRE(s==&damage); uint32_t result=damage_mode%2;
    DAMAGE_RECORD(3,previous,delay,result); return result;
}
void damage_wait(void *unused,damage_state *s,uint32_t count) {
    (void)unused; REQUIRE(s==&damage); DAMAGE_RECORD(4,count);
}
uint32_t damage_flip(void *unused,damage_state *s,font_surface *surface) {
    (void)unused; REQUIRE(s==&damage); uint32_t result=0; ++flip_calls;
    if (damage_mode==10 && flip_calls<3) result=0x8876021c;
    if (damage_mode==11) result=0x887601c2;
    if (damage_mode==12) result=0x80004005;
    DAMAGE_RECORD(5,surface_id(surface),result,damage.page);
    if (damage_mode==10 && flip_calls==1) { title.primary=&surfaces[3]; damage.page=1; }
    return result;
}
void damage_recover(void *unused,damage_state *s) {
    (void)unused; REQUIRE(s==&damage); DAMAGE_RECORD(6); damage.page=1; scene.refresh_ok=1;
}

#ifndef DX_STANDALONE
#include "damage-native.h"
static font_rect *damage_rectangle_view(font_rect *pointer) {
    uintptr_t p=(uintptr_t)pointer;
    if (p>=0x424438 && p<0x42c138) return (font_rect *)((unsigned char *)damage.history+(p-0x424438));
    if (p>=0x41c730 && p<0x424430) return (font_rect *)((unsigned char *)damage.pending+(p-0x41c730));
    return pointer;
}
static uint32_t WINAPI native_damage_fast(uint32_t destination,uint32_t x,uint32_t y,
                                         uint32_t source,font_rect *rectangle,uint32_t flags) {
    damage_from_native();
    for (uint32_t i=0;i<object_count;++i) if ((uintptr_t)rectangle==(uintptr_t)&native_sprites[i]+20) {
        REQUIRE(source==native_sprites[i].surface);
        damage_sprite_blit(NULL,&damage,title_surface_view(destination),&sprites[i],x,y,flags);
        damage_to_native(); return 0x88760001;
    }
    damage_blit_fast(NULL,&damage,title_surface_view(destination),x,y,title_surface_view(source),
        damage_rectangle_view(rectangle),flags);
    damage_to_native(); return 0x88760001;
}
static uint32_t WINAPI native_damage_blit(uint32_t destination,font_rect *dr,uint32_t source,
                                         font_rect *sr,uint32_t flags,void *effects) {
    REQUIRE(!effects); damage_from_native();
    damage_blit(NULL,&damage,title_surface_view(destination),damage_rectangle_view(dr),
        title_surface_view(source),damage_rectangle_view(sr),flags);
    damage_to_native(); return 0x88760001;
}
static uint32_t WINAPI native_damage_flip(uint32_t surface,void *target,uint32_t flags) {
    REQUIRE(!target && !flags); damage_from_native();
    uint32_t result=damage_flip(NULL,&damage,title_surface_view(surface)); damage_to_native(); return result;
}
static uint32_t native_damage_now(void) {
    damage_from_native(); uint32_t result=damage_now(NULL,&damage); damage_to_native(); return result;
}
static uint32_t native_damage_elapsed(uint32_t previous,uint32_t delay) {
    damage_from_native(); uint32_t result=damage_elapsed(NULL,&damage,previous,delay); damage_to_native(); return result;
}
static void native_damage_wait(uint32_t count) { damage_from_native(); damage_wait(NULL,&damage,count); damage_to_native(); }
static void native_damage_recover(void) { damage_from_native(); damage_recover(NULL,&damage); damage_to_native(); }
#define ROOT0(name) static void native_root_damage_##name(void) { damage_from_native(); fixture_damage_##name(&damage); damage_to_native(); }
ROOT0(reset) ROOT0(restore) ROOT0(present) ROOT0(flush)
#define ROOT_RECT(name) static void native_root_damage_##name(font_rect r) { damage_from_native(); fixture_damage_##name(&damage,&r); damage_to_native(); }
ROOT_RECT(mark) ROOT_RECT(erase) ROOT_RECT(damage)
#define ROOT_SPRITE(name) static void native_root_damage_##name(uint32_t slot,uint32_t x,uint32_t y) { \
    damage_from_native(); fixture_damage_##name(&damage,slot,x,y); damage_to_native(); }
ROOT_SPRITE(transparent) ROOT_SPRITE(opaque)
#define ROOT_SURFACE(name) static void native_root_damage_##name(uint32_t surface) { \
    damage_from_native(); fixture_damage_##name(&damage,title_surface_view(surface)); damage_to_native(); }
ROOT_SURFACE(background) ROOT_SURFACE(destination)
static void native_root_damage_sort(uint32_t first,uint32_t last) {
    damage_from_native(); fixture_damage_sort(&damage,first,last); damage_to_native();
}
static uint32_t native_root_damage_overlap(font_rect a,font_rect b) {
    damage_from_native(); uint32_t result=fixture_damage_overlap(&damage,&a,&b); damage_to_native(); return result;
}
#define DAMAGE_OPERATIONS(X) X(reset) X(transparent) X(opaque) X(mark) X(erase) X(damage) X(restore) \
    X(background) X(destination) X(present) X(flush) X(sort) X(overlap)
static void damage_install(int source) {
    (void)scene_install; title_install(source);
    font_vtable[5]=(uint32_t)(uintptr_t)native_damage_blit;
    font_vtable[7]=(uint32_t)(uintptr_t)native_damage_fast;
    font_vtable[11]=(uint32_t)(uintptr_t)native_damage_flip;
#define DAMAGE_SERVICE(name) REQUIRE(install_damage_service_##name((void (*)(void))native_damage_##name));
    DAMAGE_SERVICE(now) DAMAGE_SERVICE(elapsed) DAMAGE_SERVICE(wait) DAMAGE_SERVICE(recover)
#undef DAMAGE_SERVICE
    for (unsigned i=0;i<3;++i) *word(damage_guard_addresses[i])=damage_guards[i];
    if (!source) return;
#define ENTRY(name) REQUIRE(install_damage_##name((void (*)(void))native_root_damage_##name));
    DAMAGE_OPERATIONS(ENTRY)
#undef ENTRY
}
#endif

static uint64_t damage_local_pixels(font_surface *surface) {
    REQUIRE(surface); const unsigned char *bytes=scene_pixels(surface); uint64_t hash=UINT64_C(14695981039346656037);
    for (uint32_t i=0;i<640*480;++i) hash=(hash^bytes[i])*UINT64_C(1099511628211);
    return hash;
}
static void damage_snapshot(spx_observer *observer) {
    uint32_t values[]={damage.page,damage.count[0],damage.count[1],damage.pending_count,damage.last_tick,
        damage.clipped,damage.capability,title.fast,scene.presentation_mode,scene.refresh_ok,
        surface_id(damage.background),surface_id(title.software),surface_id(title.primary),surface_id(scene.flip)};
    spx_observe_object(observer,NULL); spx_observe_u32s(observer,"state",values,sizeof(values)/sizeof(*values));
    spx_observe_u64(observer,"primary_pixels",damage_observe_surface(title.primary,damage_local_pixels));
    spx_observe_u64(observer,"destination_pixels",damage_observe_surface(title.software,damage_local_pixels));
    spx_observe_array(observer,"history");
    for (uint32_t i=0;i<1000;++i) {
        spx_observe_array(observer,NULL);
        for (uint32_t page=0;page<2;++page) {
            const font_rect *r=&damage.history[i][page]; uint32_t words[]={r->left,r->top,r->right,r->bottom};
            spx_observe_u32s(observer,NULL,words,4);
        }
        spx_observe_end(observer);
    }
    spx_observe_end(observer); spx_observe_array(observer,"pending");
    for (uint32_t i=0;i<2000;++i) {
        const font_rect *r=&damage.pending[i]; uint32_t words[]={r->left,r->top,r->right,r->bottom};
        spx_observe_u32s(observer,NULL,words,4);
    }
    spx_observe_end(observer);
    spx_observe_u32s(observer,"keys",damage.keys,2000); spx_observe_end(observer);
}

int main(int argc,char **argv) {
    (void)snapshot; (void)damage_guard_addresses;
    REQUIRE(argc==3); damage_mode=(uint32_t)strtoul(argv[2],NULL,10); REQUIRE(damage_mode<19);
    font_setup(17+damage_mode,0); state.current_bank=0;
    for (unsigned i=0;i<sizeof(pixels);++i) ((unsigned char *)pixels)[i]=(unsigned char)(i*13+damage_mode);
    flow.overlay=&surfaces[4];
    title=(title_state){.font=&font,.palettes=&palettes,.flow=&flow,.primary=&surfaces[1],.software=&surfaces[2],
        .back=&surfaces[0],.message=message,.sine=samples,.length=sizeof(message),.palette_width=120,.fast=1};
    scene=(scene_state){.animation=&title,.flip=&surfaces[5],.presentation_mode=0};
    damage=(damage_state){.scene=&scene,.background=&surfaces[4],.page=1,.last_tick=7,.capability=1};
    memset(damage.history,0x91,sizeof(damage.history)); memset(damage.pending,0xa2,sizeof(damage.pending));
    for (uint32_t i=0;i<2000;++i) damage.keys[i]=0xf1230000+i;
    damage_clock=damage_mode==13 ? UINT32_MAX-15 : 50;
    if (damage_mode==1 || damage_mode==2 || (damage_mode>=10 && damage_mode<=13)) title.fast=0;
    if (damage_mode==2) scene.presentation_mode=1;
    if (damage_mode==3) { title.fast=2; damage.capability=UINT32_MAX; }
    if (damage_mode==4 || damage_mode==7 || damage_mode==9) damage.clipped=1;
    if (damage_mode==18) {
        title.primary=title.software=title.back=scene.flip=flow.overlay=damage.background=NULL;
    }
#ifndef DX_STANDALONE
    int source=!strcmp(argv[1],"source"); damage_install(source); damage_to_native();
#define SYNC() damage_to_native()
#define CALL0(name,address) ((void (*)(void))address)(); damage_from_native()
#define CALL_RECT(name,address,r) ((void (*)(font_rect))address)(r); damage_from_native()
#define CALL_SPRITE(name,address,slot,x,y) ((void (*)(uint32_t,uint32_t,uint32_t))address)(slot,x,y); damage_from_native()
#define CALL_SURFACE(name,address,surface) ((void (*)(uint32_t))address)(title_surface_address(surface)); damage_from_native()
#define CALL_SORT(first,last) ((void (*)(uint32_t,uint32_t))0x401930)(first,last); damage_from_native()
#define CALL_OVERLAP(a,b) ((uint32_t (*)(font_rect,font_rect))0x40d5e0)(a,b)
#else
    REQUIRE(!strcmp(argv[1],"source"));
#define SYNC() ((void)0)
#define CALL0(name,address) fixture_damage_##name(&damage)
#define CALL_RECT(name,address,r) fixture_damage_##name(&damage,&r)
#define CALL_SPRITE(name,address,slot,x,y) fixture_damage_##name(&damage,slot,x,y)
#define CALL_SURFACE(name,address,surface) fixture_damage_##name(&damage,surface)
#define CALL_SORT(first,last) fixture_damage_sort(&damage,first,last)
#define CALL_OVERLAP(a,b) fixture_damage_overlap(&damage,&a,&b)
#endif
    fputs("{\"damage\":",stdout); spx_observer o=spx_observe_begin(stdout); spx_observe_array(&o,"states");
    CALL0(reset,0x401000); damage_snapshot(&o);
    if (damage_mode==18) {
        title.primary=&surfaces[1]; title.back=&surfaces[0]; scene.flip=&surfaces[5]; flow.overlay=&surfaces[4]; SYNC();
    }
    CALL_SURFACE(background,0x401630,damage_mode==14 ? &surfaces[2] : &surfaces[4]);
    CALL_SURFACE(destination,0x401640,&surfaces[2]);
    if (damage_mode==5) { damage.count[0]=999; damage.count[1]=1000; damage.pending_count=1999; SYNC(); }
    font_rect r={21,23,41,43}; damage_stage=1;
    CALL_SPRITE(transparent,0x401080,1,51,53); CALL_SPRITE(opaque,0x401140,2,71,73);
    CALL_RECT(mark,0x401200,r); CALL_RECT(damage,0x401350,r);
    damage_stage=3; CALL_RECT(erase,0x401280,r); damage_snapshot(&o);
    REQUIRE(r.right==41 && r.bottom==43); /* Native erase takes a value, not the caller's rectangle. */
    if (damage_mode==5) { damage.count[0]=3; damage.count[1]=2; damage.pending_count=4; }
    if (damage_mode==4) {
        static const font_rect edges[]={{0xfffffffe,0xfffffffd,5,7},{638,479,650,487},{650,1,670,4},
            {5,481,8,490},{1,0xfffffffc,5,0xffffffff},{0xfffffffa,2,0xffffffff,4},{640,480,640,480},{8,8,3,3}};
        damage.count[damage.page]=sizeof(edges)/sizeof(*edges);
        for (uint32_t i=0;i<damage.count[damage.page];++i) damage.history[i][damage.page]=edges[i];
    }
    if (damage_mode==17) damage.count[0]=damage.count[1]=damage.pending_count=0;
    damage_stage=2; SYNC(); CALL0(restore,0x401430); damage_snapshot(&o);
    static const font_rect work[]={{101,103,113,115},{11,13,23,25},{22,13,34,25},
        {11,13,17,19},{600,400,620,420},{17,19,27,29},{4,9999,8,10003}};
    memcpy(damage.pending,work,sizeof(work)); damage.pending_count=sizeof(work)/sizeof(*work);
    if (damage_mode==4) { damage.pending[0]=(font_rect){0xfffffffb,0xfffffffd,5,7}; damage.pending[4]=(font_rect){638,479,650,487}; }
    if (damage_mode==14) title.primary=scene.flip;
    if (damage_mode==17) damage.pending_count=0;
    damage_stage=4; SYNC(); CALL0(flush,0x401700); damage_snapshot(&o);
    damage_stage=5; damage.last_tick=damage_mode==13 ? 0 : 7;
    damage.pending[0]=r; damage.pending_count=1; SYNC(); CALL0(present,0x401650); damage_snapshot(&o);
    /* Direct sorting has its own keys and inclusive subrange, with untouched frames. */
    static const uint32_t keys[]={99,3,UINT32_MAX,0x80000000,3,0x7fffffff,7};
    memcpy(damage.keys,keys,sizeof(keys));
    for (uint32_t i=0;i<7;++i) damage.pending[i]=(font_rect){i,10+i,20+i,30+i};
    SYNC(); CALL_SORT(1,5); CALL_SORT(0,UINT32_MAX); damage_snapshot(&o); spx_observe_end(&o);
    spx_observe_array(&o,"geometry"); uint32_t seed=0x812ab331+damage_mode;
    for (uint32_t i=0;i<128;++i) {
        font_rect a,b; uint32_t words[8];
        for (uint32_t j=0;j<8;++j) { seed=seed*1664525+1013904223; words[j]=damage_mode==16 ? seed : seed%100; }
        memcpy(&a,words,sizeof(a)); memcpy(&b,words+4,sizeof(b));
        spx_observe_u64(&o,NULL,CALL_OVERLAP(a,b));
    }
    spx_observe_end(&o); spx_observe_array(&o,"services");
    for (uint32_t i=0;i<damage_call_count;++i) spx_observe_u32s(&o,NULL,damage_calls[i],16);
    spx_observe_end(&o); spx_observe_bytes(&o,"pixels",pixels,sizeof(pixels));
#ifndef DX_STANDALONE
    for (unsigned i=0;i<3;++i) damage_guards[i]=*word(damage_guard_addresses[i]);
    if (source) {
#define INTACT(name) REQUIRE(install_damage_##name##_intact());
        DAMAGE_OPERATIONS(INTACT)
#undef INTACT
        for (unsigned i=0;i<13;++i) REQUIRE(damage_entries[i]);
    }
#endif
    spx_observe_u32s(&o,"guards",damage_guards,3); REQUIRE(spx_observe_finish(&o));
    fputs(",\"objects\":",stdout); font_observe_objects(); fputs("}\n",stdout); return 0;
}
#ifndef DX_STANDALONE
static LONG WINAPI damage_fault(EXCEPTION_POINTERS *p) {
    fprintf(stderr,"native fault %08lx at %08lx\n",p->ExceptionRecord->ExceptionCode,p->ContextRecord->Eip);
    fflush(NULL); ExitProcess(86); return EXCEPTION_EXECUTE_HANDLER;
}
static void damage_run_case(void) {
    SetUnhandledExceptionFilter(damage_fault); int count; char **args,**environment; struct native_startupinfo startup={0};
    REQUIRE(__getmainargs(&count,&args,&environment,0,&startup)==0); int result=main(count,args); fflush(NULL); ExitProcess((UINT)result);
}
__declspec(dllexport) void dx_damage_anchor(void) {}
BOOL WINAPI DllMain(HINSTANCE instance,DWORD reason,void *reserved) {
    (void)instance; (void)reserved;
    return reason!=DLL_PROCESS_ATTACH || ((uintptr_t)GetModuleHandleA(NULL)==0x400000 && install_startup(damage_run_case));
}
#endif
