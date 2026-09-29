/* Actual score.dat CRT services and the existing live game consumer. */
#define MENU_NORMAL_LIBRARY_ONLY 1
#include "menu-normal-runtime.c"
#include "scores-runtime.h"

struct spx_opaque_scores_file_v5 { uint32_t address; struct spx_opaque_scores_file_v5 *next; };
static scores_file *score_files;
static scores_state scores_live;
static uint32_t scores_entries[3],scores_depth,scores_count,scores_calls[16][3];
static unsigned char scores_bytes_after[16][660];
void scores_enter(unsigned operation) { REQUIRE(operation<3); ++scores_entries[operation]; }
static scores_file *scores_file_view(uint32_t address) {
    if (!address) return NULL;
    for (scores_file *file=score_files;file;file=file->next) if (file->address==address) return file;
    scores_file *file=malloc(sizeof(*file)); REQUIRE(file); *file=(scores_file){address,score_files}; score_files=file; return file;
}
static void scores_from_native(void) {
    memcpy(scores_live.entries,(void *)0x431cc8,660); scores_live.file=scores_file_view(*word(0x434964));
}
static void scores_to_native(void) {
    memcpy((void *)0x431cc8,scores_live.entries,660); *word(0x434964)=scores_live.file ? scores_live.file->address : 0;
}
scores_file *scores_open(void *unused,scores_state *state,uint32_t writing) {
    (void)unused; REQUIRE(state==&scores_live && writing<=1);
    uint32_t address=((uint32_t (*)(const char *,const char *))0x40e190)("score.dat",writing ? "wb" : "rb");
    return scores_file_view(address);
}
#define TRANSFER(name,entry) \
void scores_##name(void *unused,scores_state *state,scores_file *file,scores_bytes *bytes) { \
    (void)unused; REQUIRE(state==&scores_live && file && bytes->size==660 && bytes->data==(unsigned char *)state->entries); \
    ((uint32_t (*)(void *,uint32_t,uint32_t,uint32_t))(uintptr_t)entry)(bytes->data,44,15,file->address); \
}
TRANSFER(read,0x40e580) TRANSFER(write,0x40e6c0)
void scores_close(void *unused,scores_state *state,scores_file *file) {
    (void)unused; REQUIRE(state==&scores_live && file);
    ((uint32_t (*)(uint32_t))0x40df50)(file->address);
    /* The native global retains this closed identity. Never dereference it;
     * wrappers preserve equality if the CRT later reuses the same address. */
}
uint32_t scores_access(void *unused,scores_state *state,uint32_t mode) {
    (void)unused; REQUIRE(state==&scores_live); return ((uint32_t (*)(const char *,uint32_t))0x40e810)("score.dat",mode);
}
static void scores_record(unsigned operation,uint32_t rank) {
    if (scores_count==16) return;
    uint32_t i=scores_count++; scores_calls[i][0]=operation; scores_calls[i][1]=rank; scores_calls[i][2]=!!*word(0x434964);
    memcpy(scores_bytes_after[i],(void *)0x431cc8,660);
}
#define SCORES_VOID(name,operation,address) \
static void live_scores_##name(void) { \
    unsigned outer=!scores_depth++; \
    if (source_side) { scores_from_native(); fixture_scores_##name(&scores_live); scores_to_native(); } \
    else { REQUIRE(spx_fixture_restore_entry(&install_scores_##name##_hook)); ((void (*)(void))(uintptr_t)address)(); \
        install_scores_##name##_hook.entry=NULL; REQUIRE(install_scores_##name(live_scores_##name)); } \
    --scores_depth; if (outer) scores_record(operation,0); \
}
SCORES_VOID(load,0,0x409a30) SCORES_VOID(initialize,1,0x409bb0)
static uint32_t live_scores_insert(const char *name,uint32_t value) {
    unsigned outer=!scores_depth++; uint32_t result;
    if (source_side) { scores_from_native(); scores_name input={name}; result=fixture_scores_insert(&scores_live,&input,value); scores_to_native(); }
    else {
        REQUIRE(spx_fixture_restore_entry(&install_scores_insert_hook)); result=((uint32_t (*)(const char *,uint32_t))0x409a70)(name,value);
        install_scores_insert_hook.entry=NULL; REQUIRE(install_scores_insert((void (*)(void))live_scores_insert));
    }
    --scores_depth; if (outer) scores_record(2,result); return result;
}
static void scores_observe(spx_observer *o) {
    menu_observe(o); spx_observe_array(o,"score_table");
    for (uint32_t i=0;i<scores_count;++i) {
        spx_observe_object(o,NULL); spx_observe_u32s(o,"call",scores_calls[i],3);
        spx_observe_bytes(o,"records",scores_bytes_after[i],660); spx_observe_end(o);
    }
    spx_observe_end(o);
}
static void scores_diagnose(spx_observer *o) {
    menu_diagnose(o); spx_observe_u32s(o,"selected_score_table",scores_entries,3);
}
static void scores_report(void) {
    const char *path=getenv("SPX_COMPARISON_REPORT"); if (!path) return;
    FILE *out=fopen(path,"wb"); REQUIRE(out);
    fprintf(out,"{\"side\":\"%s\",\"exit_code\":0,\"observations\":",source_side ? "source" : "original");
    spx_observer o=spx_observe_begin(out); scores_observe(&o);
    REQUIRE(spx_observe_finish(&o)); fputs(",\"diagnostics\":",out); o=spx_observe_begin(out);
    scores_diagnose(&o);
    REQUIRE(spx_observe_finish(&o)); fputs("}\n",out); fclose(out);
}
static BOOL scores_main(HINSTANCE instance,DWORD reason,void *reserved) {
    if (!menu_main(instance,reason,reserved)) return FALSE;
    if (reason==DLL_PROCESS_DETACH) {
        scores_report(); while (score_files) { scores_file *next=score_files->next; free(score_files); score_files=next; } return TRUE;
    }
    if (reason!=DLL_PROCESS_ATTACH) return TRUE;
    REQUIRE(install_scores_load(live_scores_load)); REQUIRE(install_scores_initialize(live_scores_initialize));
    REQUIRE(install_scores_insert((void (*)(void))live_scores_insert)); return TRUE;
}
#ifndef SCORES_NORMAL_LIBRARY_ONLY
BOOL WINAPI DllMain(HINSTANCE instance,DWORD reason,void *reserved) {
    return scores_main(instance,reason,reserved);
}
#endif
