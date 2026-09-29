/* Application record transport; the original MDS library remains a service. */
#define READER_NORMAL_LIBRARY_ONLY 1
#include "reader-normal-runtime.c"
#include "music-runtime.h"
struct spx_opaque_music_stream_v5 { uint32_t address; };
static music_state music;
static music_stream music_streams[256];
static struct { music_record view;uint32_t address,live; } music_records[128];
static unsigned music_record_count,music_stream_count,music_depth,music_count,music_allocations,music_frees;
static void music_platform_outputs(void *context,const spx_wine_event *event) {
    (void)context;
    /* MDS header dwUser refers to its application-owned LocalAlloc record.
     * Bind the allocation's identity without putting its layout in the backend. */
    if(event->api==SPX_LOCAL_ALLOC && event->output_object)
        spx_wine_bind_midi_allocation_user(wine_environment,event->output_object);
}
static uint32_t music_entries[4];
static struct { uint32_t operation,start,result,before[4],after[4],allocations,frees;char name[128]; } music_events[256];
void music_enter(unsigned op) { REQUIRE(op<4);++music_entries[op]; }
static music_stream *music_stream_view(uint32_t address) {
    if(!address)return NULL;
    for(unsigned i=0;i<music_stream_count;++i)if(music_streams[i].address==address)return &music_streams[i];
    REQUIRE(music_stream_count<256);music_streams[music_stream_count].address=address;return &music_streams[music_stream_count++];
}
static uint32_t music_stream_address(music_stream *p) { return p ? p->address : 0; }
static unsigned music_record_index(music_record *p) {
    REQUIRE(p);for(unsigned i=0;i<music_record_count;++i)if(p==&music_records[i].view)return i;
    REQUIRE(0);return 0;
}
static music_record *music_record_view(uint32_t address) {
    if(!address)return NULL;
    for(unsigned i=music_record_count;i;--i)if(music_records[i-1].address==address)return &music_records[i-1].view;
    REQUIRE(0);return NULL;
}
static uint32_t music_record_address(music_record *p) { return p ? music_records[music_record_index(p)].address : 0; }
static void music_pull(void) {
    music.current=music_record_view(*word(0x42c144));
    for(unsigned i=0;i<music_record_count;++i)if(music_records[i].live) {
        music_records[i].view.stream=music_stream_view(*word(music_records[i].address));
        music_records[i].view.playing=*word(music_records[i].address+4);
    }
}
static void music_push(void) {
    *word(0x42c144)=music_record_address(music.current);
    for(unsigned i=0;i<music_record_count;++i)if(music_records[i].live) {
        *word(music_records[i].address)=music_stream_address(music_records[i].view.stream);
        *word(music_records[i].address+4)=music_records[i].view.playing;
    }
}
static void (*music_prior_allocation_observer)(uint32_t,uint32_t);
static void music_observed_allocate(uint32_t bytes,uint32_t address) {
    if(music_prior_allocation_observer)music_prior_allocation_observer(bytes,address);
    if(music_depth) {
        REQUIRE(bytes==8);++music_allocations;
        if(address) { REQUIRE(music_record_count<128);unsigned i=music_record_count++;music_records[i].address=address;music_records[i].live=1; }
    }
}
static void native_music_free(uint32_t address) {
    if(music_depth)++music_frees;
    for(unsigned i=music_record_count;i;--i)if(music_records[i-1].address==address && music_records[i-1].live) { music_records[i-1].live=0;break; }
    REQUIRE(spx_fixture_restore_entry(&install_music_service_free_record_hook));((void (*)(uint32_t))0x40df30)(address);
    install_music_service_free_record_hook.entry=NULL;REQUIRE(install_music_service_free_record((void (*)(void))native_music_free));
}
#define MUSIC_BEGIN() (void)u;REQUIRE(s==&music);music_push()
#define MUSIC_END() music_pull()
music_record *music_allocate_record(void *u,music_state *s,uint32_t size) {
    MUSIC_BEGIN();uint32_t address=((uint32_t (*)(uint32_t))0x40df40)(size);MUSIC_END();return music_record_view(address);
}
void music_free_record(void *u,music_state *s,music_record *record) { MUSIC_BEGIN();((void (*)(uint32_t))0x40df30)(music_record_address(record));MUSIC_END(); }
uint32_t music_load(void *u,music_state *s,music_record *record,music_name *name,uint32_t length,uint32_t flags) {
    MUSIC_BEGIN();uint32_t result=((uint32_t (*)(uint32_t,const char *,uint32_t,uint32_t))0x401a20)(music_record_address(record),name->text,length,flags);MUSIC_END();return result;
}
uint32_t music_start_stream(void *u,music_state *s,music_stream *stream,uint32_t loop) {
    MUSIC_BEGIN();uint32_t result=((uint32_t (*)(uint32_t,uint32_t))0x401ea0)(music_stream_address(stream),loop);MUSIC_END();return result;
}
#define SERVICE(name,address) uint32_t music_##name(void *u,music_state *s,music_stream *stream) { MUSIC_BEGIN();uint32_t result=((uint32_t (*)(uint32_t))address)(music_stream_address(stream));MUSIC_END();return result; }
SERVICE(pause_stream,0x401fe0) SERVICE(stop_stream,0x402030) SERVICE(release_stream,0x401e40)
#undef SERVICE
#undef MUSIC_BEGIN
#undef MUSIC_END
static void music_snapshot(uint32_t *out) {
    out[0]=music.current ? music_record_index(music.current)+1 : 0;
    out[1]=music.current ? music_records[music_record_index(music.current)].live : 0;
    out[2]=out[1] ? music.current->stream!=NULL : 0;out[3]=out[1] ? music.current->playing : 0;
}
static int music_begin(unsigned op,const char *name,uint32_t start) {
    int outer=!music_depth++;music_pull();
    if(outer) {
        REQUIRE(music_count<256);music_events[music_count].operation=op;music_events[music_count].start=start;
        if(name) { REQUIRE(strlen(name)<128);strcpy(music_events[music_count].name,name); }
        music_snapshot(music_events[music_count].before);music_events[music_count].allocations=music_allocations;music_events[music_count].frees=music_frees;
    }
    return outer;
}
static void music_end(int outer,uint32_t result) {
    music_pull();REQUIRE(music_depth);--music_depth;
    if(outer) {
        music_snapshot(music_events[music_count].after);music_events[music_count].result=result;
        music_events[music_count].allocations=music_allocations-music_events[music_count].allocations;
        music_events[music_count].frees=music_frees-music_events[music_count].frees;++music_count;
    }
}
static uint32_t live_music_play(const char *name,uint32_t start) {
    int outer=music_begin(0,name,start);uint32_t result;
    if(source_side) { music_name path={name};result=fixture_music_play(&music,&path,start);music_push();REQUIRE(install_music_play_intact()); }
    else {
        REQUIRE(spx_fixture_restore_entry(&install_music_play_hook));result=((uint32_t (*)(const char *,uint32_t))0x402100)(name,start);
        install_music_play_hook.entry=NULL;REQUIRE(install_music_play((void (*)(void))live_music_play));
    }
    music_end(outer,result);return result;
}
#define ENTRY(name,op,address) static void live_music_##name(void) { \
    int outer=music_begin(op,NULL,0); \
    if(source_side) { fixture_music_##name(&music);music_push();REQUIRE(install_music_##name##_intact()); } \
    else { REQUIRE(spx_fixture_restore_entry(&install_music_##name##_hook));((void (*)(void))address)(); \
        install_music_##name##_hook.entry=NULL;REQUIRE(install_music_##name(live_music_##name)); } \
    music_end(outer,0); }
ENTRY(resume,1,0x4021a0) ENTRY(pause,2,0x4021d0) ENTRY(stop,3,0x402200)
#undef ENTRY
static void music_observe(spx_observer *o) {
    reader_observe(o);spx_observe_array(o,"music_control");
    for(unsigned i=0;i<music_count;++i) {
        spx_observe_object(o,NULL);uint32_t args[]={music_events[i].operation,music_events[i].start,music_events[i].result,music_events[i].allocations,music_events[i].frees};
        spx_observe_u32s(o,"call",args,5);spx_observe_u32s(o,"before",music_events[i].before,4);spx_observe_u32s(o,"after",music_events[i].after,4);
        spx_observe_bytes(o,"name",(const unsigned char *)music_events[i].name,strlen(music_events[i].name));spx_observe_end(o);
    }
    spx_observe_end(o);
}
static void music_diagnose(spx_observer *o) {
    reader_diagnose(o);spx_observe_u32s(o,"selected_music",music_entries,4);
}
static void music_report(void) {
    const char *path=getenv("SPX_COMPARISON_REPORT");if(!path)return;FILE *out=fopen(path,"wb");REQUIRE(out);
    fprintf(out,"{\"side\":\"%s\",\"exit_code\":0,\"observations\":",source_side ? "source" : "original");
    spx_observer o=spx_observe_begin(out);music_observe(&o);
    REQUIRE(spx_observe_finish(&o));fputs(",\"diagnostics\":",out);o=spx_observe_begin(out);music_diagnose(&o);
    REQUIRE(spx_observe_finish(&o));fputs("}\n",out);fclose(out);
}
static BOOL music_main(HINSTANCE instance,DWORD reason,void *reserved) {
    if(!reader_main(instance,reason,reserved))return FALSE;
    if(reason==DLL_PROCESS_DETACH) { music_report();return TRUE; }
    if(reason!=DLL_PROCESS_ATTACH)return TRUE;
    REQUIRE(!*word(0x42c144));
    REQUIRE(spx_wine_install_mappings(wine_environment,NULL,SPX_WINE_MAPPINGS_ALL));
    REQUIRE(spx_wine_install_memory(wine_environment,NULL,SPX_WINE_MEMORY_ALL));
    REQUIRE(spx_wine_install_midi(wine_environment,NULL,SPX_WINE_MIDI_ALL));
    spx_wine_bind_midi_callback(wine_environment,(spx_wine_midi_callback)0x4020c0,0,1);
    spx_wine_set_hooks(wine_environment,(spx_wine_hooks){.before=audio_platform_inputs,.after=music_platform_outputs});
    music_prior_allocation_observer=normal_allocation_observer;normal_allocation_observer=music_observed_allocate;
    REQUIRE(install_music_service_free_record((void (*)(void))native_music_free));
    REQUIRE(install_music_play((void (*)(void))live_music_play));REQUIRE(install_music_resume(live_music_resume));REQUIRE(install_music_pause(live_music_pause));REQUIRE(install_music_stop(live_music_stop));return TRUE;
}
#ifndef MUSIC_NORMAL_LIBRARY_ONLY
BOOL WINAPI DllMain(HINSTANCE instance,DWORD reason,void *reserved) {
    return music_main(instance,reason,reserved);
}
#endif
