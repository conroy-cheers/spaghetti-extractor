/* Bind the reader into the existing normal program and shared Wine environment. */
#define WAVE_NORMAL_LIBRARY_ONLY 1
#include "wave-normal-runtime.c"
#include "reader-runtime.h"
static unsigned reader_selected,reader_count,reader_handle_count,reader_view_count;
static reader_handle reader_handles[256];
static reader_bytes reader_views[256];
static struct { char name[260];uint32_t allocate,supplied,returned; } reader_records[256];
void reader_enter(void) { ++reader_selected; }
static reader_bytes *reader_view(void *p) {
    if(!p)return NULL;
    REQUIRE(reader_view_count<256);reader_views[reader_view_count].bytes=p;return &reader_views[reader_view_count++];
}
reader_handle *reader_open(void *u,reader_name *name,uint32_t access,uint32_t share,uint32_t disposition,uint32_t attributes) {
    (void)u;uintptr_t value=spx_wine_file_open(wine_environment,name->text,access,share,NULL,disposition,attributes,0);
    if(value==SPX_WINE_INVALID_HANDLE)return NULL;
    REQUIRE(reader_handle_count<256);reader_handles[reader_handle_count].value=value;return &reader_handles[reader_handle_count++];
}
uint32_t reader_size(void *u,reader_handle *file) { (void)u;return spx_wine_file_size(wine_environment,file->value,NULL); }
reader_bytes *reader_allocate(void *u,uint32_t size) {
    (void)u;return reader_view(((void *(*)(uint32_t))0x40e2f0)(size));
}
uint32_t reader_read(void *u,reader_handle *file,reader_bytes *buffer,uint32_t size) {
    (void)u;uint32_t count=0;return spx_wine_file_read(wine_environment,file->value,buffer ? buffer->bytes : NULL,size,&count,NULL);
}
void reader_free(void *u,reader_bytes *buffer) { (void)u;((void (*)(void *))0x40e2a0)(buffer ? buffer->bytes : NULL); }
void reader_close(void *u,reader_handle *file) { (void)u;(void)spx_wine_file_close(wine_environment,file->value); }
static void *live_file_reader(const char *name,void *supplied,uint32_t allocate) {
    REQUIRE(reader_count<256 && strlen(name)<=256);unsigned record=reader_count++;
    strcpy(reader_records[record].name,name);reader_records[record].allocate=allocate;reader_records[record].supplied=supplied!=NULL;
    void *result;
    if(source_side) {
        reader_name path={name};reader_bytes *bytes=fixture_file_read(&path,reader_view(supplied),allocate);result=bytes ? bytes->bytes : NULL;
        REQUIRE(install_file_reader_intact());
    } else {
        REQUIRE(spx_fixture_restore_entry(&install_file_reader_hook));result=((void *(*)(const char *,void *,uint32_t))0x40d9f0)(name,supplied,allocate);
        install_file_reader_hook.entry=NULL;REQUIRE(install_file_reader((void (*)(void))live_file_reader));
    }
    reader_records[record].returned=result!=NULL;return result;
}
static void reader_observe(spx_observer *o) {
    wave_observe(o);spx_observe_array(o,"file_reads");
    for(unsigned i=0;i<reader_count;++i) {
        spx_observe_object(o,NULL);spx_observe_bytes(o,"name",(const unsigned char *)reader_records[i].name,strlen(reader_records[i].name));
        uint32_t values[]={reader_records[i].allocate,reader_records[i].supplied,reader_records[i].returned};spx_observe_u32s(o,"arguments_result",values,3);spx_observe_end(o);
    }
    spx_observe_end(o);
}
static void reader_diagnose(spx_observer *o) { wave_diagnose(o);spx_observe_u64(o,"selected_reader",reader_selected); }
static void reader_report(void) {
    const char *path=getenv("SPX_COMPARISON_REPORT");if(!path)return;FILE *out=fopen(path,"wb");REQUIRE(out);
    fprintf(out,"{\"side\":\"%s\",\"exit_code\":0,\"observations\":",source_side ? "source" : "original");
    spx_observer o=spx_observe_begin(out);reader_observe(&o);REQUIRE(spx_observe_finish(&o));fputs(",\"diagnostics\":",out);
    o=spx_observe_begin(out);reader_diagnose(&o);REQUIRE(spx_observe_finish(&o));fputs("}\n",out);fclose(out);
}
static BOOL reader_main(HINSTANCE instance,DWORD reason,void *reserved) {
    if(!wave_main(instance,reason,reserved))return FALSE;
    if(reason==DLL_PROCESS_DETACH) { reader_report();return TRUE; }
    if(reason!=DLL_PROCESS_ATTACH)return TRUE;
    REQUIRE(!memcmp((const void *)0x416064,"..\\",4));
    REQUIRE(spx_wine_install_files(wine_environment,NULL,SPX_WINE_FILES_ALL|SPX_WINE_FILES_NATIVE_UNBOUND_CLOSE));
    REQUIRE(install_file_reader((void (*)(void))live_file_reader));return TRUE;
}

#ifndef READER_NORMAL_LIBRARY_ONLY
BOOL WINAPI DllMain(HINSTANCE instance,DWORD reason,void *reserved) { return reader_main(instance,reason,reserved); }
#endif
