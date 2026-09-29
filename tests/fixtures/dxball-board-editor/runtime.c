/* Connected editor consumer with explicit board, input and rendering services. */
#define MENU_TEXT_CAPACITY 256
#define MENU_LIBRARY_ONLY 1
#include "menu-runtime.c"
#include "editor-runtime.h"
#ifdef EDITOR_REGION_COMPONENT
#include "regions-runtime.h"
static uint32_t region_entries[3];
void regions_enter(unsigned operation) { REQUIRE(operation<3); ++region_entries[operation]; }
#endif

struct spx_opaque_board_file_v5 { uint32_t id,writing,open; };
static board_file editor_files[2]={{1,0,0},{2,1,0}};
static board_set editor_boards;
static board_editor editor={.menu=&menu,.boards=&editor_boards};
static uint32_t editor_mode,editor_entries[7],board_entries[5],editor_calls[1200][8],editor_count,editor_callback_used;
static unsigned char editor_disk[20000];
static uint32_t editor_disk_size=20000;
void editor_enter(unsigned operation) { REQUIRE(operation<7); ++editor_entries[operation]; }
void board_enter(unsigned operation) { REQUIRE(operation<5); ++board_entries[operation]; }
#define EDITOR_RECORD(...) do { const uint32_t values[]={__VA_ARGS__}; REQUIRE(editor_count<1200); \
    memcpy(editor_calls[editor_count++],values,sizeof(values)); } while (0)
#define EDITOR_PUSH() ((void)0)
#define EDITOR_PULL() ((void)0)
#include "editor-common.h"
static uint32_t editor_file_id(board_file *file) {
    if (!file) return 0;
    REQUIRE(file==&editor_files[0] || file==&editor_files[1]); return file->id;
}
board_file *board_open(void *unused,board_set *s,board_name *name,uint32_t writing) {
    (void)unused; REQUIRE(s==&editor_boards && !strcmp(name->text,"default.bds") && writing<2);
    board_file *file=(editor_mode==8 && !writing) || (editor_mode==9 && writing) ? NULL : &editor_files[writing];
    EDITOR_RECORD(0,writing,editor_file_id(file),editor_file_id(s->file));
    if (file) { REQUIRE(!file->open); file->open=1; if (writing) editor_disk_size=0; }
    return file;
}
void board_read(void *unused,board_set *s,board_file *file,board_bytes *bytes) {
    (void)unused; REQUIRE(s==&editor_boards && file && file->open && !file->writing);
    REQUIRE(bytes->data==(unsigned char *)s->saved && bytes->size==20000);
    uint32_t size=editor_mode==10 ? 277 : editor_disk_size;
    EDITOR_RECORD(1,editor_file_id(file),size); memcpy(bytes->data,editor_disk,size);
}
void board_write(void *unused,board_set *s,board_file *file,board_bytes *bytes) {
    (void)unused; REQUIRE(s==&editor_boards && file && file->open && file->writing);
    REQUIRE(bytes->data==(unsigned char *)s->saved && bytes->size==20000);
    EDITOR_RECORD(2,editor_file_id(file),20000); memcpy(editor_disk,bytes->data,20000); editor_disk_size=20000;
}
void board_close(void *unused,board_set *s,board_file *file) {
    (void)unused; REQUIRE(s==&editor_boards && file && file->open); EDITOR_RECORD(3,editor_file_id(file)); file->open=0;
}
#define EDITOR_BOARD_COPY(name) \
void editor_##name##_board(void *unused,board_set *s,uint32_t index) { (void)unused; REQUIRE(s==&editor_boards && index<50); fixture_board_##name(s,index); }
EDITOR_BOARD_COPY(select) EDITOR_BOARD_COPY(store)
#define EDITOR_BOARD_IO(name) \
void editor_##name##_boards(void *unused,board_set *s,board_name *name) { (void)unused; fixture_board_##name(s,name); }
EDITOR_BOARD_IO(load) EDITOR_BOARD_IO(save)
uint32_t editor_sprite_id(void *unused,uint32_t kind) { (void)unused; return fixture_board_sprite(kind); }
void editor_sprite(void *unused,menu_state *s,uint32_t slot,uint32_t x,uint32_t y) {
    (void)unused; REQUIRE(s==&menu); (void)fixture_sprite_opaque(&font,slot,x,y);
}
void editor_reset_regions(void *unused,board_editor *s,uint32_t count) {
    (void)unused; REQUIRE(s==&editor && count==23); EDITOR_RECORD(4,count);
#ifdef EDITOR_REGION_COMPONENT
    region_table regions={&s->region_count,s->regions,25}; fixture_regions_reset(&regions,count);
#else
    s->region_count=count+1; memset(s->regions,0,sizeof(s->regions));
#endif
}
void editor_define_region(void *unused,board_editor *s,uint32_t index,font_rect *rectangle) {
    (void)unused; REQUIRE(s==&editor && index<25); EDITOR_RECORD(5,index,rectangle->left,rectangle->top,rectangle->right,rectangle->bottom);
#ifdef EDITOR_REGION_COMPONENT
    region_table regions={&s->region_count,s->regions,25};
    fixture_regions_define(&regions,index,rectangle->left,rectangle->top,rectangle->right,rectangle->bottom);
#else
    s->regions[index]=(editor_region){rectangle->left,rectangle->top,rectangle->right,rectangle->bottom,1};
#endif
}
uint32_t editor_hit_region(void *unused,board_editor *s,uint32_t x,uint32_t y) {
    (void)unused; REQUIRE(s==&editor && s->region_count<=25); uint32_t hit=0;
#ifdef EDITOR_REGION_COMPONENT
    region_table regions={&s->region_count,s->regions,25}; hit=fixture_regions_hit(&regions,x,y);
#else
    for (uint32_t i=1;i<s->region_count;++i) {
        const editor_region *r=&s->regions[i];
        if (r->enabled && font_signed(x)>=font_signed(r->left) && font_signed(x)<=font_signed(r->right)
            && font_signed(y)>=font_signed(r->top) && font_signed(y)<=font_signed(r->bottom)) hit=i;
    }
#endif
    EDITOR_RECORD(6,x,y,hit); return hit;
}
void editor_cursor(void *unused,board_editor *s,uint32_t slot,uint32_t x,uint32_t y) {
    (void)unused; REQUIRE(s==&editor); EDITOR_RECORD(7,slot,x,y);
}
static void editor_cell_pixels(uint32_t column,uint32_t row) {
    REQUIRE(column<20 && row<20);
    fill_pixels(font.destination,20+30*column,50+15*row,49+30*column,64+15*row,editor_boards.current.cells[row][column]);
}
void editor_draw_board(void *unused,board_editor *s,uint32_t mode) {
    (void)unused; REQUIRE(s==&editor && !mode); EDITOR_RECORD(8,mode);
    fixture_sprite_destination(&font,title.back);
    for (uint32_t column=0;column<20;++column) for (uint32_t row=0;row<20;++row) editor_cell_pixels(column,row);
}
void editor_draw_cell(void *unused,board_editor *s,uint32_t column,uint32_t row,uint32_t mode) {
    (void)unused; REQUIRE(s==&editor && !mode); EDITOR_RECORD(9,column,row,mode,s->boards->current.cells[row][column]);
    editor_cell_pixels(column,row);
    if (editor_mode==13 && !editor_callback_used++) { scene.mouse_buttons=2; menu.input_ready=1; editor.index=49; }
}
static void editor_redraw_callback(scene_state *s) { REQUIRE(s==&scene); fixture_editor_redraw(&editor); }

#ifndef DX_STANDALONE
static uint32_t editor_file_address(board_file *file) { return (uint32_t)(uintptr_t)file; }
static board_file *editor_file_view(uint32_t address) { return (board_file *)(uintptr_t)address; }
#include "editor-native.h"
static uint32_t native_editor_open(const char *name,const char *mode) {
    REQUIRE(!strcmp(mode,"rb") || !strcmp(mode,"wb")); editor_from_native(); board_name path={name};
    board_file *file=board_open(NULL,&editor_boards,&path,!strcmp(mode,"wb")); editor_to_native(); return editor_file_address(file);
}
#define EDITOR_FILE_TRANSFER(name) \
static uint32_t native_editor_##name(void *data,uint32_t size,uint32_t count,board_file *file) { \
    REQUIRE(data==(void *)0x42cdf8 && size==1 && count==20000); editor_from_native(); \
    board_bytes bytes={(unsigned char *)editor_boards.saved,20000}; board_##name(NULL,&editor_boards,file,&bytes); editor_to_native(); return count; \
}
EDITOR_FILE_TRANSFER(read) EDITOR_FILE_TRANSFER(write)
static uint32_t native_editor_close(board_file *file) { editor_from_native(); board_close(NULL,&editor_boards,file); editor_to_native(); return 0; }
#define EDITOR_CALLBACK(name,parameters,...) static void native_editor_##name parameters { \
    editor_from_native(); editor_##name(NULL,&editor,__VA_ARGS__); editor_to_native(); }
EDITOR_CALLBACK(reset_regions,(uint32_t count),count)
EDITOR_CALLBACK(cursor,(uint32_t slot,uint32_t x,uint32_t y),slot,x,y)
EDITOR_CALLBACK(draw_board,(uint32_t mode),mode)
EDITOR_CALLBACK(draw_cell,(uint32_t column,uint32_t row,uint32_t mode),column,row,mode)
static void native_editor_define_region(uint32_t index,uint32_t left,uint32_t top,uint32_t right,uint32_t bottom) {
    editor_from_native(); font_rect rectangle={left,top,right,bottom}; editor_define_region(NULL,&editor,index,&rectangle); editor_to_native();
}
static uint32_t native_editor_hit_region(uint32_t x,uint32_t y) {
    editor_from_native(); uint32_t result=editor_hit_region(NULL,&editor,x,y); editor_to_native(); return result;
}
#define EDITOR_ROOT(name) static void native_root_editor_##name(void) { editor_from_native(); fixture_editor_##name(&editor); editor_to_native(); }
EDITOR_ROOT(enter) EDITOR_ROOT(redraw) EDITOR_ROOT(update) EDITOR_ROOT(draw_palette) EDITOR_ROOT(draw_status)
#define EDITOR_ARG_ROOT(name) static void native_root_editor_##name(uint32_t value) { editor_from_native(); fixture_editor_##name(&editor,value); editor_to_native(); }
EDITOR_ARG_ROOT(key) EDITOR_ARG_ROOT(leave)
#define EDITOR_BOARD_ROOT(name) static void native_editor_board_##name(uint32_t index) { editor_from_native(); fixture_board_##name(&editor_boards,index); editor_to_native(); }
EDITOR_BOARD_ROOT(select) EDITOR_BOARD_ROOT(store)
#define EDITOR_BOARD_IO_ROOT(name) static void native_editor_board_##name(const char *filename) { \
    editor_from_native(); board_name path={filename}; fixture_board_##name(&editor_boards,&path); editor_to_native(); }
EDITOR_BOARD_IO_ROOT(load) EDITOR_BOARD_IO_ROOT(save)
static uint32_t native_editor_board_sprite(uint32_t kind) { return fixture_board_sprite(kind); }
static void editor_install(int source) {
    menu_install(source); scene_redraw_address=0x403660;
#define EDITOR_FILE(name) REQUIRE(install_board_service_##name((void (*)(void))native_editor_##name));
    EDITOR_FILE(open) EDITOR_FILE(read) EDITOR_FILE(write) EDITOR_FILE(close)
#define EDITOR_SERVICE(name) REQUIRE(install_editor_service_##name((void (*)(void))native_editor_##name));
    EDITOR_SERVICE(reset_regions) EDITOR_SERVICE(define_region) EDITOR_SERVICE(hit_region)
    EDITOR_SERVICE(cursor) EDITOR_SERVICE(draw_board) EDITOR_SERVICE(draw_cell)
    if (!source) return;
#define EDITOR_INSTALL(name) REQUIRE(install_editor_##name((void (*)(void))native_root_editor_##name));
    EDITOR_INSTALL(enter) EDITOR_INSTALL(redraw) EDITOR_INSTALL(update) EDITOR_INSTALL(key)
    EDITOR_INSTALL(draw_palette) EDITOR_INSTALL(draw_status) EDITOR_INSTALL(leave)
#define EDITOR_BOARD_INSTALL(name) REQUIRE(install_board_##name((void (*)(void))native_editor_board_##name));
    EDITOR_BOARD_INSTALL(load) EDITOR_BOARD_INSTALL(save) EDITOR_BOARD_INSTALL(select) EDITOR_BOARD_INSTALL(store) EDITOR_BOARD_INSTALL(sprite)
}
#endif

static void editor_snapshot(spx_observer *o) {
    spx_observe_object(o,NULL); spx_observe_array(o,"scene"); snapshot(o); spx_observe_end(o);
    uint32_t values[]={editor.selected_tile,editor.index,editor.region_count,menu.input_ready,editor_file_id(editor_boards.file),
        editor_files[0].open,editor_files[1].open,editor_disk_size};
    spx_observe_u32s(o,"fields",values,8); spx_observe_bytes(o,"current",(const unsigned char *)&editor_boards.current,400);
    spx_observe_bytes(o,"saved",(const unsigned char *)editor_boards.saved,20000);
    spx_observe_array(o,"regions");
    for (uint32_t i=0;i<25;++i) { editor_region *r=&editor.regions[i]; uint32_t v[]={r->left,r->top,r->right,r->bottom,r->enabled}; spx_observe_u32s(o,NULL,v,5); }
    spx_observe_end(o); spx_observe_end(o);
}
int main(int argc,char **argv) {
    REQUIRE(argc==3); editor_mode=(uint32_t)strtoul(argv[2],NULL,10); REQUIRE(editor_mode<16);
    font_setup(17+editor_mode,0);
    /* The inherited font bank only contains five glyphs. The admitted editor
     * bank must also own the actual tile slots used by its palette. */
    for (uint32_t slot=6;slot<=60;++slot) {
        uint32_t id=object_count++; REQUIRE(object_count<=OBJECTS);
        font_sprite *sprite=&sprites[id]; state.banks[0].slots[slot]=sprite; live[id]=1;
        sprite->surface=&surfaces[4]; ++refs[4]; memset(sprite->retained,0,sizeof(sprite->retained));
        put_word(sprite,8,30); put_word(sprite,12,15); put_word(sprite,28,30); put_word(sprite,32,15);
    }
    state.banks[0].count=61;
    memset(pixels,0x35,sizeof(pixels)); memset(&palettes,0x77,sizeof(palettes));
    flow.overlay=&surfaces[4]; flow.scene=2; flow.next_scene=2;
    title=(title_state){.font=&font,.palettes=&palettes,.flow=&flow,.primary=&surfaces[1],.software=&surfaces[2],
        .back=&surfaces[0],.message=message,.sine=samples,.length=sizeof(message),.palette_width=120,.fast=1};
    scene=(scene_state){.animation=&title,.flip=&surfaces[5],.presentation_mode=editor_mode==12 ? 2 : editor_mode%2,
        .mouse_x=editor_mode==4 ? 0xfffffff0 : editor_mode==5 ? 20 : editor_mode==15 ? 116 : editor_mode==11 ? 20 : 21,
        .mouse_y=editor_mode==4 ? 0xfffffffe : editor_mode==5 ? 385 : editor_mode==15 ? 419 : 51,
        .mouse_buttons=editor_mode==6 ? 2 : editor_mode==12 ? 3 : 1};
    menu=(menu_state){.scene=&scene,.cosine=cosine,.input_ready=editor_mode==1 || editor_mode==13}; menu.offsets[359][1]=guards[0];
    scene_image_name="mbbkgrnd.pcx"; scene_bank_names[0]="mball2.sbk"; scene_bank_names[1]="sfont.sbk";
    scene_bank_names[2]="mainmenu.sbk"; scene_redraw_callback=editor_redraw_callback;
    for (unsigned i=0;i<20000;++i) editor_disk[i]=(unsigned char)(i%23);
    if (editor_mode==14) { FILE *input=fopen("default.bds","rb"); REQUIRE(input && fread(editor_disk,1,20000,input)==20000); fclose(input); }
    memcpy(editor_boards.saved,editor_disk,20000); memset(&editor_boards.current,0xa5,400); editor_boards.file=&editor_files[1];
#ifndef DX_STANDALONE
    int source=!strcmp(argv[1],"source"); editor_install(source); editor_to_native();
#define EDITOR_CALL(name,address) ((void (*)(void))(uintptr_t)address)(); editor_from_native(); editor_snapshot(&o)
#define EDITOR_ARG(name,address,value) ((void (*)(uint32_t))(uintptr_t)address)(value); editor_from_native(); editor_snapshot(&o)
#define EDITOR_SYNC() editor_to_native()
#else
    REQUIRE(!strcmp(argv[1],"source"));
#define EDITOR_CALL(name,address) fixture_editor_##name(&editor); editor_snapshot(&o)
#define EDITOR_ARG(name,address,value) fixture_editor_##name(&editor,value); editor_snapshot(&o)
#define EDITOR_SYNC() ((void)0)
#endif
    fputs("{\"editor\":",stdout); spx_observer o=spx_observe_begin(stdout); spx_observe_array(&o,"states");
    EDITOR_CALL(enter,0x403570); editor.index=editor_mode==2 ? 49 : 0; editor.selected_tile=editor_mode==3 ? 0 : 2;
    EDITOR_SYNC(); EDITOR_CALL(update,0x403750); EDITOR_CALL(update,0x403750);
    uint32_t keys[]={'P','N',8,'S','L',0x80,0x1234004e};
    for (unsigned i=0;i<sizeof(keys)/sizeof(keys[0]);++i) { EDITOR_ARG(key,0x403a00,keys[i]); }
    EDITOR_CALL(draw_palette,0x403b60); EDITOR_CALL(draw_status,0x403bd0); EDITOR_CALL(redraw,0x403660);
    EDITOR_ARG(leave,0x403f30,0); EDITOR_ARG(leave,0x403f30,1);
    spx_observe_end(&o); spx_observe_array(&o,"calls");
    for (uint32_t i=0;i<editor_count;++i) spx_observe_u32s(&o,NULL,editor_calls[i],8);
    spx_observe_end(&o); spx_observe_array(&o,"scene_calls");
    for (uint32_t i=0;i<scene_count;++i) spx_observe_u32s(&o,NULL,scene_calls[i],14);
    spx_observe_end(&o); spx_observe_array(&o,"menu_calls");
    for (uint32_t i=0;i<menu_count;++i) spx_observe_u32s(&o,NULL,menu_calls[i],8);
    spx_observe_end(&o); spx_observe_array(&o,"drawing_calls");
    for (uint32_t i=0;i<call_count;++i) spx_observe_u32s(&o,NULL,title_calls[i],12);
    spx_observe_end(&o); spx_observe_array(&o,"font_blits");
    for (uint32_t i=0;i<blit_count;++i) spx_observe_u32s(&o,NULL,blits[i],12);
    spx_observe_end(&o); spx_observe_array(&o,"text");
    for (uint32_t i=0;i<text_count;++i) {
        spx_observe_object(&o,NULL); spx_observe_u32s(&o,"position",text_calls[i],4);
        spx_observe_bytes(&o,"bytes",text_bytes[i],text_lengths[i]); spx_observe_end(&o);
    }
    spx_observe_end(&o); spx_observe_bytes(&o,"disk",editor_disk,editor_disk_size);
    spx_observe_bytes(&o,"pixels",pixels,sizeof(pixels)); REQUIRE(spx_observe_finish(&o));
    guards[2]=editor_file_id(editor_boards.file); fputs(",\"objects\":",stdout); font_observe_objects(); fputs("}\n",stdout);
#ifdef EDITOR_REGION_COMPONENT
    for (unsigned i=0;i<3;++i) REQUIRE(region_entries[i]);
#endif
#ifndef DX_STANDALONE
    if (source) {
        REQUIRE(install_editor_enter_intact() && install_editor_redraw_intact() && install_editor_update_intact()
            && install_editor_key_intact() && install_editor_draw_palette_intact() && install_editor_draw_status_intact() && install_editor_leave_intact());
        for (unsigned i=0;i<7;++i) REQUIRE(editor_entries[i]);
        for (unsigned i=0;i<5;++i) REQUIRE(board_entries[i]);
    }
#endif
    return 0;
}
#ifndef DX_STANDALONE
static LONG WINAPI editor_fault(EXCEPTION_POINTERS *p) {
    fprintf(stderr,"native fault %08lx at %08lx\n",p->ExceptionRecord->ExceptionCode,p->ContextRecord->Eip);
    fflush(NULL); ExitProcess(86); return EXCEPTION_EXECUTE_HANDLER;
}
static void editor_run_case(void) {
    SetUnhandledExceptionFilter(editor_fault); int count; char **args,**environment; struct native_startupinfo startup={0};
    REQUIRE(__getmainargs(&count,&args,&environment,0,&startup)==0); int result=main(count,args); fflush(NULL); ExitProcess((UINT)result);
}
__declspec(dllexport) void dx_editor_anchor(void) {}
BOOL WINAPI DllMain(HINSTANCE instance,DWORD reason,void *reserved) {
    (void)instance; (void)reserved;
    return reason!=DLL_PROCESS_ATTACH || ((uintptr_t)GetModuleHandleA(NULL)==0x400000 && install_startup(editor_run_case));
}
#endif
