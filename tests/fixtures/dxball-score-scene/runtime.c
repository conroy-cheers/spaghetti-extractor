/* Connected screen consumer: original native bodies versus ordinary C callers. */
#define MENU_TEXT_CAPACITY 256
#define MENU_LIBRARY_ONLY 1
#include "menu-runtime.c"
#include "screen-runtime.h"

struct spx_opaque_scores_file_v5 { uint32_t identity,writing,open; };
static scores_file screen_files[2]={{1,0,0},{2,1,0}};
static scores_state scores_live;
static score_screen screen={.menu=&menu,.scores=&scores_live};
static uint32_t screen_mode,screen_entries[6],scores_entries[3];
static unsigned char screen_disk[660];
static uint32_t file_calls[64][4],file_count;
#define SCREEN_PUSH() ((void)0)
#define SCREEN_PULL() ((void)0)
#include "screen-common.h"
void screen_enter(unsigned operation) { REQUIRE(operation<6); ++screen_entries[operation]; }
void scores_enter(unsigned operation) { REQUIRE(operation<3); ++scores_entries[operation]; }
static void screen_file_event(uint32_t event,uint32_t a,uint32_t b,uint32_t c) {
    REQUIRE(file_count<64); uint32_t row[]={event,a,b,c}; memcpy(file_calls[file_count++],row,sizeof(row));
}
static uint32_t screen_file_id(scores_file *file) {
    if (!file) return 0;
    REQUIRE(file==&screen_files[0] || file==&screen_files[1]); return file->identity;
}
scores_file *scores_open(void *unused,scores_state *s,uint32_t writing) {
    (void)unused; REQUIRE(s==&scores_live && writing<2);
    scores_file *file=(screen_mode==16 && !writing) || (screen_mode==17 && writing) ? NULL : &screen_files[writing];
    screen_file_event(0,writing,screen_file_id(file),0);
    if (file) { REQUIRE(!file->open); file->open=1; if (writing) memset(screen_disk,0,660); }
    return file;
}
void scores_read(void *unused,scores_state *s,scores_file *file,scores_bytes *bytes) {
    (void)unused; REQUIRE(s==&scores_live && file && file->open && !file->writing && bytes->size==660 && bytes->data==(unsigned char *)s->entries);
    screen_file_event(1,screen_file_id(file),660,0); memcpy(bytes->data,screen_disk,660);
}
void scores_write(void *unused,scores_state *s,scores_file *file,scores_bytes *bytes) {
    (void)unused; REQUIRE(s==&scores_live && file && file->open && file->writing && bytes->size==660 && bytes->data==(unsigned char *)s->entries);
    screen_file_event(2,screen_file_id(file),660,0); memcpy(screen_disk,bytes->data,660);
}
void scores_close(void *unused,scores_state *s,scores_file *file) {
    (void)unused; REQUIRE(s==&scores_live && file && file->open); screen_file_event(3,screen_file_id(file),0,0); file->open=0;
}
uint32_t scores_access(void *unused,scores_state *s,uint32_t mode) {
    (void)unused; REQUIRE(s==&scores_live && (mode==0 || mode==2));
    uint32_t result=screen_mode==18 ? UINT32_MAX : 0; screen_file_event(4,mode,result,0); return result;
}
uint32_t screen_measure(void *unused,font_state *s,uint32_t length,font_bytes *bytes) {
    (void)unused; return fixture_font_measure(s,length,bytes);
}
void screen_load_scores(void *unused,scores_state *s) { (void)unused; fixture_scores_load(s); }
uint32_t screen_insert_score(void *unused,scores_state *s,scores_name *name,uint32_t value) {
    (void)unused; return fixture_scores_insert(s,name,value);
}
void screen_damage(void *unused,score_screen *s,font_rect *rectangle) {
    (void)unused; REQUIRE(s==&screen); MENU_RECORD(9,rectangle->left,rectangle->top,rectangle->right,rectangle->bottom);
}
static void screen_redraw_callback(scene_state *s) { REQUIRE(s==&scene); fixture_screen_redraw(&screen); }

#ifndef DX_STANDALONE
static void scores_to_native(void) {
    memcpy((void *)0x431cc8,scores_live.entries,660); *word(0x434964)=(uint32_t)(uintptr_t)scores_live.file;
}
static void scores_from_native(void) {
    memcpy(scores_live.entries,(void *)0x431cc8,660); scores_live.file=(scores_file *)(uintptr_t)*word(0x434964);
}
#include "screen-native.h"
static uint32_t native_screen_open(const char *name,const char *mode) {
    REQUIRE(!strcmp(name,"score.dat") && (!strcmp(mode,"rb") || !strcmp(mode,"wb"))); scores_from_native();
    scores_file *file=scores_open(NULL,&scores_live,!strcmp(mode,"wb")); scores_to_native(); return (uint32_t)(uintptr_t)file;
}
#define FILE_TRANSFER(name) \
static uint32_t native_screen_##name(void *data,uint32_t size,uint32_t count,scores_file *file) { \
    REQUIRE(data==(void *)0x431cc8 && size==44 && count==15); scores_from_native(); \
    scores_bytes bytes={(unsigned char *)scores_live.entries,660}; scores_##name(NULL,&scores_live,file,&bytes); scores_to_native(); return 15; \
}
FILE_TRANSFER(read) FILE_TRANSFER(write)
static uint32_t native_screen_close(scores_file *file) { scores_from_native(); scores_close(NULL,&scores_live,file); scores_to_native(); return 0; }
static uint32_t native_screen_access(const char *name,uint32_t mode) {
    REQUIRE(!strcmp(name,"score.dat")); scores_from_native(); uint32_t result=scores_access(NULL,&scores_live,mode); scores_to_native(); return result;
}
static void native_screen_damage(font_rect rectangle) { screen_from_native(); screen_damage(NULL,&screen,&rectangle); screen_to_native(); }
static void native_screen_load_scores(void) { scores_from_native(); fixture_scores_load(&scores_live); scores_to_native(); }
static void native_screen_initialize_scores(void) { scores_from_native(); fixture_scores_initialize(&scores_live); scores_to_native(); }
static uint32_t native_screen_insert_score(const char *name,uint32_t value) {
    scores_from_native(); scores_name input={name}; uint32_t result=fixture_scores_insert(&scores_live,&input,value); scores_to_native(); return result;
}
#define SCREEN_ROOT(name) static void native_root_screen_##name(void) { screen_from_native(); fixture_screen_##name(&screen); screen_to_native(); }
SCREEN_ROOT(enter) SCREEN_ROOT(redraw) SCREEN_ROOT(update) SCREEN_ROOT(draw_table)
#define KEY_ROOT(name) static void native_root_screen_##name(uint32_t key) { screen_from_native(); fixture_screen_##name(&screen,key); screen_to_native(); }
KEY_ROOT(key) KEY_ROOT(edit)
static void screen_install(int source) {
    menu_install(source); scene_redraw_address=0x409510;
#define FILE_SERVICE(name) REQUIRE(install_scores_service_##name((void (*)(void))native_screen_##name));
    FILE_SERVICE(open) FILE_SERVICE(read) FILE_SERVICE(write) FILE_SERVICE(close) FILE_SERVICE(access)
    REQUIRE(install_screen_damage((void (*)(void))native_screen_damage));
    if (!source) return;
#define SCREEN_INSTALL(name) REQUIRE(install_screen_##name((void (*)(void))native_root_screen_##name));
    SCREEN_INSTALL(enter) SCREEN_INSTALL(redraw) SCREEN_INSTALL(update) SCREEN_INSTALL(key) SCREEN_INSTALL(draw_table) SCREEN_INSTALL(edit)
    REQUIRE(install_scores_load(native_screen_load_scores)); REQUIRE(install_scores_initialize(native_screen_initialize_scores));
    REQUIRE(install_scores_insert((void (*)(void))native_screen_insert_score));
}
#endif

static void screen_snapshot(spx_observer *o) {
    spx_observe_object(o,NULL); spx_observe_array(o,"scene"); snapshot(o); spx_observe_end(o);
    uint32_t values[]={menu.score,screen.length,screen.blink,screen.entering,screen.last_tick,screen.show_table,screen.highlight,screen.shift,
        screen_file_id(scores_live.file),screen_files[0].open,screen_files[1].open};
    spx_observe_u32s(o,"fields",values,11); spx_observe_bytes(o,"name",(const unsigned char *)screen.name,40);
    spx_observe_bytes(o,"records",(const unsigned char *)scores_live.entries,660); spx_observe_bytes(o,"disk",screen_disk,660);
    spx_observe_end(o);
}
int main(int argc,char **argv) {
    REQUIRE(argc==3); screen_mode=(uint32_t)strtoul(argv[2],NULL,10); REQUIRE(screen_mode<20);
    font_setup(17+screen_mode,0); menu_mode=screen_mode==3 ? 0 : screen_mode==4 ? 1 : 2;
    memset(pixels,0x36,sizeof(pixels)); memset(&palettes,0x77,sizeof(palettes));
    flow.overlay=&surfaces[4]; flow.scene=3; flow.next_scene=3;
    title=(title_state){.font=&font,.palettes=&palettes,.flow=&flow,.primary=&surfaces[1],.software=&surfaces[2],
        .back=&surfaces[0],.message=message,.sine=samples,.length=sizeof(message),.palette_width=120,.fast=1};
    scene=(scene_state){.animation=&title,.flip=&surfaces[5],.presentation_mode=screen_mode%2,
        .mouse_x=screen_mode==11 ? 0xfffffff0 : 620,.mouse_y=screen_mode==11 ? 0xfffffffe : 448,.mouse_buttons=screen_mode%4};
    menu=(menu_state){.scene=&scene,.cosine=cosine,.score=screen_mode==0 || screen_mode==15 ? 0 : screen_mode==1 ? 10 :
        screen_mode==2 ? UINT32_MAX : 120,.input_ready=1}; menu.offsets[359][1]=guards[0];
    menu_track_name="acker-gs.mds"; scene_image_name="highscor.pcx"; scene_bank_names[0]="mainmenu.sbk";
    scene_bank_names[1]="sysfont.sbk"; scene_redraw_callback=screen_redraw_callback;
    screen.shift=screen_mode==8 ? 1 : screen_mode==9 ? 2 : 0; memset(screen.name,0xa5,40); screen.name[0]=0;
    for (unsigned i=0;i<15;++i) {
        score_entry *entry=&scores_live.entries[i]; memset(entry,0x80+i,44);
        entry->name[0]=(char)('A'+i%3); entry->name[1]=0; score_set_value(entry,150-10*i);
    }
    memcpy(screen_disk,scores_live.entries,660);
    if (screen_mode==19) { FILE *input=fopen("score.dat","rb"); REQUIRE(input && fread(screen_disk,1,660,input)==660); fclose(input); }
#ifndef DX_STANDALONE
    int source=!strcmp(argv[1],"source"); screen_install(source); screen_to_native();
#define SCREEN_CALL(name,address) ((void (*)(void))(uintptr_t)address)(); screen_from_native(); screen_snapshot(&o)
#define SCREEN_KEY(name,address,key) ((void (*)(uint32_t))(uintptr_t)address)(key); screen_from_native(); screen_snapshot(&o)
#define SYNC_SCREEN() screen_to_native()
#else
    REQUIRE(!strcmp(argv[1],"source"));
#define SCREEN_CALL(name,address) fixture_screen_##name(&screen); screen_snapshot(&o)
#define SCREEN_KEY(name,address,key) fixture_screen_##name(&screen,key); screen_snapshot(&o)
#define SYNC_SCREEN() ((void)0)
#endif
    fputs("{\"screen\":",stdout); spx_observer o=spx_observe_begin(stdout); spx_observe_array(&o,"states");
    SCREEN_CALL(enter,0x409410);
    if (screen_mode==5) { memset(screen.name,'X',30); screen.name[30]=0; screen.length=30; }
    if (screen_mode==7) { screen.entering=2; screen.show_table=2; }
    screen.blink=screen_mode%3; screen.last_tick=0xfffffffa; clock_value=0xfffffff0;
    SYNC_SCREEN();
    uint32_t keys[]={8,0x141,'Z',' ','7',8,'b',0x80};
    for (unsigned i=0;i<sizeof(keys)/sizeof(keys[0]);++i) { SCREEN_KEY(key,0x4098e0,keys[i]); }
    SCREEN_CALL(update,0x4096a0);
    /* Direct edit is also a genuine native entry; low-byte Return includes the
     * rejected-insertion path even when the outer key dispatcher is disabled. */
    SCREEN_KEY(edit,0x409f80,0xabcd000d);
    screen.highlight=screen_mode==13 ? 14 : screen_mode==14 ? 0 : screen.highlight; SYNC_SCREEN();
    SCREEN_CALL(redraw,0x409510); SCREEN_CALL(draw_table,0x409900);
    scene.mouse_buttons=1; SYNC_SCREEN(); SCREEN_CALL(update,0x4096a0);
    scene.mouse_buttons=2; SYNC_SCREEN(); SCREEN_CALL(update,0x4096a0);
    spx_observe_end(&o); spx_observe_array(&o,"calls");
    for (uint32_t i=0;i<menu_count;++i) spx_observe_u32s(&o,NULL,menu_calls[i],8);
    spx_observe_end(&o); spx_observe_array(&o,"scene_calls");
    for (uint32_t i=0;i<scene_count;++i) spx_observe_u32s(&o,NULL,scene_calls[i],14);
    spx_observe_end(&o); spx_observe_array(&o,"file_calls");
    for (uint32_t i=0;i<file_count;++i) spx_observe_u32s(&o,NULL,file_calls[i],4);
    spx_observe_end(&o); spx_observe_array(&o,"font_blits");
    for (uint32_t i=0;i<blit_count;++i) spx_observe_u32s(&o,NULL,blits[i],12);
    spx_observe_end(&o); spx_observe_array(&o,"text");
    for (uint32_t i=0;i<text_count;++i) {
        spx_observe_object(&o,NULL); spx_observe_u32s(&o,"position",text_calls[i],4);
        spx_observe_bytes(&o,"bytes",text_bytes[i],text_lengths[i]); spx_observe_end(&o);
    }
    spx_observe_end(&o); spx_observe_bytes(&o,"pixels",pixels,sizeof(pixels)); REQUIRE(spx_observe_finish(&o));
    /* This formerly independent canary is the shared CRT file cell, retained
     * after close; normalize its identity, while the table keeps all byte backing. */
    guards[2]=screen_file_id(scores_live.file); fputs(",\"objects\":",stdout); font_observe_objects(); fputs("}\n",stdout);
#ifndef DX_STANDALONE
    if (source) {
        REQUIRE(install_screen_enter_intact() && install_screen_redraw_intact() && install_screen_update_intact()
            && install_screen_key_intact() && install_screen_draw_table_intact() && install_screen_edit_intact());
        REQUIRE(install_scores_load_intact() && install_scores_insert_intact());
        for (unsigned i=0;i<6;++i) REQUIRE(screen_entries[i]);
    }
#endif
    return 0;
}
#ifndef DX_STANDALONE
static LONG WINAPI screen_fault(EXCEPTION_POINTERS *p) {
    fprintf(stderr,"native fault %08lx at %08lx\n",p->ExceptionRecord->ExceptionCode,p->ContextRecord->Eip);
    fflush(NULL); ExitProcess(86); return EXCEPTION_EXECUTE_HANDLER;
}
static void screen_run_case(void) {
    SetUnhandledExceptionFilter(screen_fault); int count; char **args,**environment; struct native_startupinfo startup={0};
    REQUIRE(__getmainargs(&count,&args,&environment,0,&startup)==0); int result=main(count,args); fflush(NULL); ExitProcess((UINT)result);
}
__declspec(dllexport) void dx_screen_anchor(void) {}
BOOL WINAPI DllMain(HINSTANCE instance,DWORD reason,void *reserved) {
    (void)instance; (void)reserved;
    return reason!=DLL_PROCESS_ATTACH || ((uintptr_t)GetModuleHandleA(NULL)==0x400000 && install_startup(screen_run_case));
}
#endif
