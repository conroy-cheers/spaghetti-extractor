/* Native entry comparisons need a grid and graphics services, not a game UI. */
#define TITLE_CALL_CAPACITY 1024
#define MENU_LIBRARY_ONLY 1
#include "menu-runtime.c"
#include "render-runtime.h"
static board_set render_boards;
static board_renderer renderer={.menu=&menu,.boards=&render_boards};
static uint32_t render_mode,render_entries[2],render_callbacks;
void render_enter(unsigned operation) { REQUIRE(operation<2); ++render_entries[operation]; }
static void render_callback(font_rect *rectangle) {
    if ((render_mode==4 || render_mode==5) && !render_callbacks++) {
        flow.scene=1; font.destination=&surfaces[1]; title.back=&surfaces[3];
        render_boards.current.cells[1][0]=7; render_boards.current.cells[2][0]=255;
        if (render_mode==5) { rectangle->right-=2; rectangle->bottom-=1; }
    }
}
void render_sprite_destination(void *unused,scene_state *s,font_surface *surface) {
    scene_sprite_destination(unused,s,surface);
}
void render_sprite(void *unused,menu_state *s,uint32_t slot,uint32_t x,uint32_t y) {
    (void)unused; REQUIRE(s==&menu); (void)fixture_sprite_opaque(&font,slot,x,y);
}
void render_blit_fast(void *unused,menu_state *s,font_surface *destination,uint32_t x,uint32_t y,
                      font_surface *source,font_rect *rectangle,uint32_t flags) {
    menu_blit_fast(unused,s,destination,x,y,source,rectangle,flags); render_callback(rectangle);
}
void render_damage(void *unused,menu_state *s,font_rect *rectangle) { menu_damage(unused,s,rectangle); }

#ifndef DX_STANDALONE
static void render_to_native(void) {
    menu_to_native(); *word(0x431fd0)=flow.scene;
    memcpy((void *)0x42ca60,&render_boards.current,400); memcpy((void *)0x42cdf8,render_boards.saved,20000);
}
static void render_from_native(void) {
    menu_from_native(); flow.scene=*word(0x431fd0);
    memcpy(&render_boards.current,(void *)0x42ca60,400); memcpy(render_boards.saved,(void *)0x42cdf8,20000);
}
static uint32_t WINAPI native_render_fast(uint32_t destination,uint32_t x,uint32_t y,
                                        uint32_t source,font_rect *rectangle,uint32_t flags) {
    render_from_native();
    title_blit_fast(NULL,&title,title_surface_view(destination),x,y,title_surface_view(source),rectangle,flags);
    render_callback(rectangle); render_to_native(); return 0x88760001;
}
static void native_render_draw(uint32_t mode) {
    render_from_native(); fixture_render_draw(&renderer,mode); render_to_native();
}
static void native_render_cell(uint32_t column,uint32_t row,uint32_t mode) {
    render_from_native(); fixture_render_cell(&renderer,column,row,mode); render_to_native();
}
#endif

static void render_snapshot(spx_observer *o) {
    uint32_t values[]={flow.scene,surface_id(font.destination),surface_id(title.back),state.current_bank};
    spx_observe_u32s(o,NULL,values,4);
}
int main(int argc,char **argv) {
    (void)snapshot;
    REQUIRE(argc==3); render_mode=(uint32_t)strtoul(argv[2],NULL,10); REQUIRE(render_mode<8);
    font_setup(17+render_mode,0); state.current_bank=0;
    for (uint32_t slot=6;slot<=60;++slot) {
        uint32_t id=object_count++; REQUIRE(object_count<=OBJECTS);
        font_sprite *sprite=&sprites[id]; state.banks[0].slots[slot]=sprite; live[id]=1;
        sprite->surface=&surfaces[4]; ++refs[4]; memset(sprite->retained,0,sizeof(sprite->retained));
        put_word(sprite,8,30); put_word(sprite,12,15); put_word(sprite,28,30); put_word(sprite,32,15);
    }
    state.banks[0].count=61;
    for (unsigned i=0;i<sizeof(pixels);++i) ((unsigned char *)pixels)[i]=(unsigned char)(i*13+render_mode);
    memset(&palettes,0x77,sizeof(palettes));
    flow.overlay=render_mode==3 ? &surfaces[0] : &surfaces[4]; flow.scene=render_mode==1 ? 1 : 2;
    title=(title_state){.font=&font,.palettes=&palettes,.flow=&flow,.primary=&surfaces[1],.software=&surfaces[2],
        .back=&surfaces[0],.message=message,.sine=samples,.length=sizeof(message),.palette_width=120,.fast=1};
    scene=(scene_state){.animation=&title,.flip=&surfaces[5],.presentation_mode=1};
    menu=(menu_state){.scene=&scene,.cosine=cosine};
    /* The last offset word aliases the cleanup table's preceding guard. Both
     * views must describe the same initial native backing. */
    menu.offsets[359][1]=guards[0];
    for (uint32_t row=0;row<20;++row) for (uint32_t col=0;col<20;++col)
        render_boards.current.cells[row][col]=(unsigned char)((row*20+col)%(render_mode==6 ? 256 : 23));
    for (unsigned i=0;i<20000;++i) ((unsigned char *)render_boards.saved)[i]=(unsigned char)(i*17+31);
    if (render_mode==7) { FILE *input=fopen("default.bds","rb"); REQUIRE(input && fread(&render_boards.current,1,400,input)==400); fclose(input); }
#ifndef DX_STANDALONE
    int source=!strcmp(argv[1],"source"); menu_install(source); font_vtable[7]=(uint32_t)(uintptr_t)native_render_fast;
    if (source) {
        REQUIRE(install_render_draw((void (*)(void))native_render_draw));
        REQUIRE(install_render_cell((void (*)(void))native_render_cell));
    }
    render_to_native();
#define RENDER_DRAW(mode) ((void (*)(uint32_t))0x405a90)(mode); render_from_native()
#define RENDER_CELL(column,row,mode) ((void (*)(uint32_t,uint32_t,uint32_t))0x405ad0)(column,row,mode); render_from_native()
#define RENDER_SYNC() render_to_native()
#else
    REQUIRE(!strcmp(argv[1],"source"));
#define RENDER_DRAW(mode) fixture_render_draw(&renderer,mode)
#define RENDER_CELL(column,row,mode) fixture_render_cell(&renderer,column,row,mode)
#define RENDER_SYNC() ((void)0)
#endif
    fputs("{\"rendering\":",stdout); spx_observer o=spx_observe_begin(stdout); spx_observe_array(&o,"states");
    RENDER_DRAW(render_mode==2 ? 1 : 0); render_snapshot(&o);
    /* All 256 byte values, including negative x86 char values, at one cell. */
    for (uint32_t kind=0;kind<256;++kind) {
        render_boards.current.cells[19][19]=(unsigned char)kind; RENDER_SYNC();
        RENDER_CELL(19,19,render_mode==6 ? UINT32_MAX : 0); render_snapshot(&o);
    }
    spx_observe_end(&o); spx_observe_array(&o,"graphics");
    for (uint32_t i=0;i<call_count;++i) spx_observe_u32s(&o,NULL,title_calls[i],12);
    spx_observe_end(&o); spx_observe_array(&o,"damage");
    for (uint32_t i=0;i<menu_count;++i) spx_observe_u32s(&o,NULL,menu_calls[i],8);
    spx_observe_end(&o); spx_observe_bytes(&o,"current",(const unsigned char *)&render_boards.current,400);
    spx_observe_bytes(&o,"saved",(const unsigned char *)render_boards.saved,20000);
    spx_observe_bytes(&o,"pixels",pixels,sizeof(pixels)); REQUIRE(spx_observe_finish(&o));
    fputs(",\"objects\":",stdout); font_observe_objects(); fputs("}\n",stdout);
#ifndef DX_STANDALONE
    if (source) REQUIRE(install_render_draw_intact() && install_render_cell_intact() && render_entries[0] && render_entries[1]);
#endif
    return 0;
}
#ifndef DX_STANDALONE
static LONG WINAPI render_fault(EXCEPTION_POINTERS *p) {
    fprintf(stderr,"native fault %08lx at %08lx\n",p->ExceptionRecord->ExceptionCode,p->ContextRecord->Eip);
    fflush(NULL); ExitProcess(86); return EXCEPTION_EXECUTE_HANDLER;
}
static void render_run_case(void) {
    SetUnhandledExceptionFilter(render_fault); int count; char **args,**environment; struct native_startupinfo startup={0};
    REQUIRE(__getmainargs(&count,&args,&environment,0,&startup)==0); int result=main(count,args); fflush(NULL); ExitProcess((UINT)result);
}
__declspec(dllexport) void dx_render_anchor(void) {}
BOOL WINAPI DllMain(HINSTANCE instance,DWORD reason,void *reserved) {
    (void)instance; (void)reserved;
    return reason!=DLL_PROCESS_ATTACH || ((uintptr_t)GetModuleHandleA(NULL)==0x400000 && install_startup(render_run_case));
}
#endif
