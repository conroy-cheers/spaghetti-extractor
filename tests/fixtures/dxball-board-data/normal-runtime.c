/* Existing game consumer with real CRT file services and byte-backed boards. */
#define SCREEN_NORMAL_LIBRARY_ONLY 1
#include "screen-normal-runtime.c"
#include "board-runtime.h"
struct spx_opaque_board_file_v5 { uint32_t address; struct spx_opaque_board_file_v5 *next; };
static board_file *board_files;
static board_set board_live;
static uint32_t board_entries[5],board_count,board_calls[32][3],board_sprite_count,board_sprites[4096][2];
static unsigned char board_bytes_after[32][20400];
void board_enter(unsigned operation) { REQUIRE(operation<5); ++board_entries[operation]; }
static board_file *board_file_view(uint32_t address) {
    if (!address) return NULL;
    for (board_file *file=board_files;file;file=file->next) if (file->address==address) return file;
    board_file *file=malloc(sizeof(*file)); REQUIRE(file); *file=(board_file){address,board_files}; board_files=file; return file;
}
static void board_from_native(void) {
    memcpy(&board_live.current,(void *)0x42ca60,400); memcpy(board_live.saved,(void *)0x42cdf8,20000);
    board_live.file=board_file_view(*word(0x434964));
}
static void board_to_native(void) {
    memcpy((void *)0x42ca60,&board_live.current,400); memcpy((void *)0x42cdf8,board_live.saved,20000);
    *word(0x434964)=board_live.file ? board_live.file->address : 0;
}
board_file *board_open(void *unused,board_set *state,board_name *name,uint32_t writing) {
    (void)unused; REQUIRE(state==&board_live && writing<2);
    return board_file_view(((uint32_t (*)(const char *,const char *))0x40e190)(name->text,writing ? "wb" : "rb"));
}
#define BOARD_TRANSFER(name,entry) \
void board_##name(void *unused,board_set *state,board_file *file,board_bytes *bytes) { \
    (void)unused; REQUIRE(state==&board_live && file && bytes->size==20000 && bytes->data==(unsigned char *)state->saved); \
    ((uint32_t (*)(void *,uint32_t,uint32_t,uint32_t))(uintptr_t)entry)(bytes->data,1,20000,file->address); \
}
BOARD_TRANSFER(read,0x40e580) BOARD_TRANSFER(write,0x40e6c0)
void board_close(void *unused,board_set *state,board_file *file) {
    (void)unused; REQUIRE(state==&board_live && file); ((uint32_t (*)(uint32_t))0x40df50)(file->address);
}
static void board_record(unsigned operation,uint32_t argument) {
    if (board_count==32) return;
    uint32_t i=board_count++; board_calls[i][0]=operation; board_calls[i][1]=argument; board_calls[i][2]=!!*word(0x434964);
    memcpy(board_bytes_after[i],(void *)0x42ca60,400); memcpy(board_bytes_after[i]+400,(void *)0x42cdf8,20000);
}
#define BOARD_IO(name,operation,address) \
static void live_board_##name(const char *filename) { \
    if (source_side) { board_from_native(); board_name path={filename}; fixture_board_##name(&board_live,&path); board_to_native(); } \
    else { REQUIRE(spx_fixture_restore_entry(&install_board_##name##_hook)); ((void (*)(const char *))(uintptr_t)address)(filename); \
        install_board_##name##_hook.entry=NULL; REQUIRE(install_board_##name((void (*)(void))live_board_##name)); } \
    board_record(operation,0); \
}
BOARD_IO(load,0,0x403d50) BOARD_IO(save,1,0x403d90)
#define BOARD_COPY(name,operation,address) \
static void live_board_##name(uint32_t index) { \
    REQUIRE(index<50); \
    if (source_side) { board_from_native(); fixture_board_##name(&board_live,index); board_to_native(); } \
    else { REQUIRE(spx_fixture_restore_entry(&install_board_##name##_hook)); ((void (*)(uint32_t))(uintptr_t)address)(index); \
        install_board_##name##_hook.entry=NULL; REQUIRE(install_board_##name((void (*)(void))live_board_##name)); } \
    board_record(operation,index); \
}
BOARD_COPY(select,2,0x403ed0) BOARD_COPY(store,3,0x403f00)
static uint32_t live_board_sprite(uint32_t kind) {
    uint32_t result;
    if (source_side) result=fixture_board_sprite(kind);
    else {
        REQUIRE(spx_fixture_restore_entry(&install_board_sprite_hook)); result=((uint32_t (*)(uint32_t))0x403dd0)(kind);
        install_board_sprite_hook.entry=NULL; REQUIRE(install_board_sprite((void (*)(void))live_board_sprite));
    }
    if (board_sprite_count<4096) { board_sprites[board_sprite_count][0]=kind; board_sprites[board_sprite_count++][1]=result; }
    return result;
}
static void board_observe(spx_observer *o) {
    scores_observe(o); spx_observe_array(o,"score_screen");
    for (uint32_t i=0;i<screen_count;++i) {
        spx_observe_object(o,NULL); spx_observe_u32s(o,"call",screen_calls[i],25);
        spx_observe_bytes(o,"name",screen_names[i],40); spx_observe_bytes(o,"records",screen_records[i],660); spx_observe_end(o);
    }
    spx_observe_end(o); spx_observe_array(o,"boards");
    for (uint32_t i=0;i<board_count;++i) {
        spx_observe_object(o,NULL); spx_observe_u32s(o,"call",board_calls[i],3);
        spx_observe_bytes(o,"bytes",board_bytes_after[i],20400); spx_observe_end(o);
    }
    spx_observe_end(o); spx_observe_array(o,"board_sprites");
    for (uint32_t i=0;i<board_sprite_count;++i) spx_observe_u32s(o,NULL,board_sprites[i],2);
    spx_observe_end(o);
}
static void board_diagnose(spx_observer *o) {
    scores_diagnose(o); spx_observe_u32s(o,"selected_score_screen",screen_entries,6);
    spx_observe_u32s(o,"score_screen_clock",screen_ticks,screen_count); spx_observe_u32s(o,"selected_board_data",board_entries,5);
}
static void board_report(void) {
    const char *path=getenv("SPX_COMPARISON_REPORT"); if (!path) return;
    FILE *out=fopen(path,"wb"); REQUIRE(out);
    fprintf(out,"{\"side\":\"%s\",\"exit_code\":0,\"observations\":",source_side ? "source" : "original");
    spx_observer o=spx_observe_begin(out); board_observe(&o);
    REQUIRE(spx_observe_finish(&o)); fputs(",\"diagnostics\":",out); o=spx_observe_begin(out); board_diagnose(&o);
    REQUIRE(spx_observe_finish(&o)); fputs("}\n",out); fclose(out);
}
static BOOL board_main(HINSTANCE instance,DWORD reason,void *reserved) {
    if (!screen_main(instance,reason,reserved)) return FALSE;
    if (reason==DLL_PROCESS_DETACH) {
        board_report(); while (board_files) { board_file *next=board_files->next; free(board_files); board_files=next; } return TRUE;
    }
    if (reason!=DLL_PROCESS_ATTACH) return TRUE;
#define BOARD_INSTALL(name) REQUIRE(install_board_##name((void (*)(void))live_board_##name));
    BOARD_INSTALL(load) BOARD_INSTALL(save) BOARD_INSTALL(select) BOARD_INSTALL(store) BOARD_INSTALL(sprite)
    return TRUE;
}
#ifndef BOARD_NORMAL_LIBRARY_ONLY
BOOL WINAPI DllMain(HINSTANCE instance,DWORD reason,void *reserved) {
    return board_main(instance,reason,reserved);
}
#endif
