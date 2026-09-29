#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define REQUIRE(x) do { if(!(x)) { fprintf(stderr,"MDS loader boundary line %d: %s\n",__LINE__,#x);abort(); } } while(0)
#define MDS_PARSER_NORMAL 1
#include "mds-transport.c"
#include "loader-transport.c"
#ifndef DX_STANDALONE
#include <windows.h>
#include "native-image.h"
#endif
static uint32_t selected,parser_selected,events_selected;static int source_side;
void loader_enter(void) { ++selected; }
void parser_enter(void) { ++parser_selected; }
void mds_events_enter(void) { ++events_selected; }
static uint32_t parser_do_expand(mds_event_block *input,mds_event_block *output) { return fixture_mds_expand(input,output); }
static uint32_t run_parser(uint32_t *info,const unsigned char *bytes,uint32_t length) {
    parser_begin(info,spx_wine_memory_storage(parser_environment,info).identity);uint32_t result;
#ifndef DX_STANDALONE
    if(!source_side) {
        REQUIRE(spx_fixture_restore_entry(&install_mds_parse_hook));
        result=((uint32_t (*)(uint32_t *,const unsigned char *,uint32_t))0x401b60)(info,bytes,length);
        install_mds_parse_hook.entry=NULL;REQUIRE(install_mds_parse((void (*)(void))run_parser));
    } else
#endif
    { mds_file file={bytes};result=fixture_mds_parse(&parser_current->view,&file,length);parser_push(); }
    parser_active=0;loader_snapshot();return result;
}
static uint32_t loader_do_parse(mds_info *info,mds_file *file,uint32_t length) {
    return run_parser(loader_record_view(info)->info->raw,file->data,length);
}
static unsigned char storage[1048577];
static uint32_t make_file(unsigned char *p,unsigned mode) {
    memset(p,0x5c,512);
    uint32_t words[]={0x46464952,60,0x5344494d,0x20746d66,12,96,32,1,0x61746164,28,1,0,16,7,0x02000000,9,0x02000000};
    for(unsigned i=0;i<sizeof(words)/sizeof(*words);++i)parser_store(p+4*i,words[i]);
    if(mode==12 || mode==13 || mode==20 || mode==21)parser_store(p,0);
    if(mode==16) { parser_store(p+48,12);parser_store(p+4,56);parser_store(p+36,24);return 64; }
    if(mode==27)parser_store(p+28,0);
    return sizeof(words);
}
static void rule(enum spx_wine_api api,uint32_t occurrence,uint32_t result) {
    spx_wine_add_rule(parser_environment,(spx_wine_rule){.api=api,.occurrence=occurrence,.flags=SPX_RULE_RETURN|SPX_RULE_ERROR,.result=result,.last_error=8});
}
#ifndef DX_STANDALONE
static uint32_t replaced_load(uint32_t *slot,const unsigned char *input,uint32_t length,uint32_t flags) {
    mds_output output={loader_info(*slot)};mds_input data={input};
    uint32_t result=fixture_mds_load(&output,&data,length,flags);*slot=loader_address(output.value);return result;
}
#endif
int main(int argc,char **argv) {
    REQUIRE(argc==3);unsigned mode=(unsigned)strtoul(argv[2],NULL,10);source_side=!strcmp(argv[1],"source");
    REQUIRE(mode<29 || (mode>=100 && mode<112));
    parser_environment=spx_wine_create(SPX_WINE_CONTROLLED);spx_wine_allocation_history(parser_environment,0x5a);
    spx_wine_set_hooks(parser_environment,(spx_wine_hooks){.before=loader_before,.after=loader_after});
    unsigned char *bytes=storage+(mode==28);uint32_t length,extent;
    if(mode>=100) {
        const char *names[]={"12flight.mds","Acker-gs.mds","Brain.mds","Ethno_pa.mds","Freebee.mds","Gmfigaro.mds"};
        FILE *f=fopen(names[(mode-100)%6],"rb");REQUIRE(f);size_t size=fread(bytes,1,1048576,f);
        REQUIRE(!ferror(f) && feof(f));fclose(f);length=extent=(uint32_t)size;
    } else { length=make_file(bytes,mode);extent=512; }
    uint32_t flags=mode==1 || mode==5 || (mode>=7 && mode<=11) || mode==13 || (mode>=14 && mode<=19) || mode==26 || mode>=106 ? 1 : 2;
    if(mode==2)flags=0;
    if(mode==3)flags=3;
    if(mode==4 || mode==5)flags|=0xaaffff00;
    if(mode==6 || mode==7)rule(SPX_LOCAL_ALLOC,1,0);
    if(mode==8)rule(SPX_FILE_OPEN_A,1,UINT32_MAX);
    if(mode==9)rule(SPX_FILE_SIZE,1,UINT32_MAX);
    if(mode==10)rule(SPX_FILE_MAPPING_A,1,0);
    if(mode==11)rule(SPX_FILE_MAP,1,0);
    if(mode==14)rule(SPX_GLOBAL_ALLOC,1,0);
    if(mode==15)rule(SPX_GLOBAL_LOCK,1,0);
    if(mode==17)rule(SPX_FILE_UNMAP,1,0);
    if(mode==18 || mode==19)rule(SPX_HANDLE_CLOSE,mode==18 ? 1 : 2,0);
    if(mode==20)rule(SPX_LOCAL_FREE,1,1);
    if(mode==25)length=0;
    spx_wine_seed_file(parser_environment,"test.mds",bytes,mode==26 ? 0 : length);
#ifndef DX_STANDALONE
    REQUIRE(spx_wine_install_memory(parser_environment,NULL,SPX_WINE_MEMORY_ALL));
    REQUIRE(spx_wine_install_files(parser_environment,NULL,SPX_WINE_FILES_ALL));
    REQUIRE(spx_wine_install_mappings(parser_environment,NULL,SPX_WINE_MAPPINGS_ALL));
    REQUIRE(install_mds_parse((void (*)(void))run_parser));
    if(source_side)REQUIRE(install_mds_load((void (*)(void))replaced_load));
    SetLastError(0);
#else
    REQUIRE(source_side);
#endif
    uint32_t slot=mode==21 || mode==22 ? 0x12345678 : 0,results[2],outputs[2];unsigned calls=mode==23 || mode==24 ? 2 : 1;
    for(unsigned i=0;i<calls;++i) {
        if(i && mode==24)parser_store(bytes,0);
        loader_active=1;loader_current=NULL;
        const unsigned char *input=(flags&3)==1 ? (const unsigned char *)"test.mds" : bytes;
#ifndef DX_STANDALONE
        results[i]=((uint32_t (*)(uint32_t *,const unsigned char *,uint32_t,uint32_t))0x401a20)(&slot,input,length,flags);
        if(source_side)REQUIRE(install_mds_load_intact() && selected==i+1);
#else
        mds_output output={loader_info(slot)};mds_input data={input};results[i]=fixture_mds_load(&output,&data,length,flags);slot=loader_address(output.value);
#endif
        loader_snapshot();outputs[i]=loader_identity(slot);loader_active=0;
    }
    spx_observer o=spx_observe_begin(stdout);spx_observe_object(&o,"mds_loader");
    spx_observe_u32s(&o,"results",results,calls);spx_observe_u32s(&o,"outputs",outputs,calls);
    spx_observe_bytes(&o,"input",bytes,extent);loader_observe(&o);spx_wine_observe(parser_environment,&o,"platform");
    spx_observe_end(&o);REQUIRE(spx_observe_finish(&o));puts("");
    if(source_side)REQUIRE(selected==calls);
    parser_dispose_views();spx_wine_destroy(parser_environment);return 0;
}
#ifndef DX_STANDALONE
struct native_startupinfo { int newmode; };
extern int __cdecl __getmainargs(int *,char ***,char ***,int,struct native_startupinfo *);
static void run_case(void) {
    int argc;char **argv,**environment;struct native_startupinfo startup={0};REQUIRE(!__getmainargs(&argc,&argv,&environment,0,&startup));
    int result=main(argc,argv);fflush(NULL);ExitProcess((UINT)result);
}
__declspec(dllexport) void dx_mds_loader_anchor(void) {}
BOOL WINAPI DllMain(HINSTANCE instance,DWORD reason,void *reserved) {
    (void)instance;(void)reserved;return reason!=DLL_PROCESS_ATTACH || ((uintptr_t)GetModuleHandleA(NULL)==0x400000 && install_startup(run_case));
}
#endif
