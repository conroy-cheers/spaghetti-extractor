#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define REQUIRE(x) do { if(!(x)) { fprintf(stderr,"MDS parser boundary line %d\n",__LINE__);abort(); } } while(0)
#include "mds-transport.c"
#ifndef DX_STANDALONE
#include <windows.h>
#include "native-image.h"
#endif
static uint32_t parser_selected,events_selected;
void parser_enter(void) { ++parser_selected; }
void mds_events_enter(void) { ++events_selected; }
static uint32_t parser_do_expand(mds_event_block *input,mds_event_block *output) { return fixture_mds_expand(input,output); }
static uint32_t native_info[9];
static unsigned char file_storage[1048576];
static uint32_t make_file(unsigned char *p,unsigned mode) {
    memset(p,0xb6,512);uint32_t format_size=mode==11 ? 16 : 12,capacity=32,format=1,count=2;
    if(mode==1 || mode==28)format=mode==1 ? 0 : 0x100;
    if(mode==21)capacity=8;
    if(mode==29)capacity=17;
    if(mode==30)capacity=0;
    if(mode==3)count=0;
    if(mode==33)count=0x40000000;
    if(mode==34)capacity=0xffffffc0;
    parser_store(p,mode==5 ? 0 : 0x46464952);parser_store(p+8,mode==6 ? 0 : 0x5344494d);
    parser_store(p+12,mode==8 ? 0 : 0x20746d66);parser_store(p+16,format_size);
    parser_store(p+20,96);parser_store(p+24,capacity);parser_store(p+28,format);
    uint32_t data=20+format_size,at=data+12;parser_store(p+data,mode==12 ? 0 : 0x61746164);parser_store(p+data+8,count);
    for(unsigned i=0;i<2;++i) {
        uint32_t bytes=mode==2 || mode==30 ? 0 : mode==19 || mode==25 || mode==26 ? 4 : mode==20 ? 7 : mode==27 ? 12 : 8;
        parser_store(p+at,100+i);parser_store(p+at+4,bytes);at+=8;
        parser_store(p+at,7+i);parser_store(p+at+4,mode==27 ? 0x80000003 : 0x02000000);parser_store(p+at+8,0xee030201);at+=bytes;
    }
    parser_store(p+data+4,at-data-8);uint32_t length=at;
    if(mode==4)length=11;
    if(mode==9)parser_store(p+16,11);
    if(mode==10)parser_store(p+16,512);
    if(mode==13)parser_store(p+data+4,3);
    if(mode==14)parser_store(p+data+4,512);
    if(mode==15) { length=data+8;parser_store(p+data+4,4); }
    if(mode==16) { length=data+16;parser_store(p+data+4,4); }
    if(mode==17)parser_store(p+data+16,36);
    if(mode==18) { length=data+24;parser_store(p+data+4,4); }
    if(mode==22) { length=data+32;parser_store(p+data+4,4); }
    parser_store(p+4,mode==7 ? 512 : length>=8 ? length-8 : 0);return length;
}
#ifndef DX_STANDALONE
static uint32_t replaced_parse(uint32_t *info,const unsigned char *bytes,uint32_t length) {
    REQUIRE(info==parser_current->raw);parser_pull();mds_file file={bytes};
    uint32_t result=fixture_mds_parse(&parser_current->view,&file,length);parser_push();return result;
}
#endif
int main(int argc,char **argv) {
    REQUIRE(argc==3);unsigned mode=(unsigned)strtoul(argv[2],NULL,10);int source=!strcmp(argv[1],"source");
    parser_environment=spx_wine_create(SPX_WINE_CONTROLLED);spx_wine_allocation_history(parser_environment,0x5a);
    spx_wine_set_hooks(parser_environment,(spx_wine_hooks){.before=parser_before,.after=parser_after});
    if(mode==23 || mode==24 || mode==25 || mode==26)spx_wine_add_rule(parser_environment,(spx_wine_rule){
        .api=mode==23 ? SPX_GLOBAL_ALLOC : mode==24 ? SPX_GLOBAL_LOCK : mode==25 ? SPX_GLOBAL_UNLOCK : SPX_GLOBAL_FREE,
        .flags=SPX_RULE_RETURN|SPX_RULE_ERROR,.result=mode==26 ? 1 : 0,.last_error=8});
    unsigned char *file=file_storage+(mode==35);uint32_t length,extent;
    if(mode>=100) {
        const char *names[]={"12flight.mds","Acker-gs.mds","Brain.mds","Ethno_pa.mds","Freebee.mds","Gmfigaro.mds"};
        REQUIRE(mode<106);FILE *f=fopen(names[mode-100],"rb");REQUIRE(f);size_t bytes=fread(file,1,sizeof(file_storage),f);
        REQUIRE(!ferror(f) && feof(f));fclose(f);length=extent=(uint32_t)bytes;
    } else { REQUIRE(mode<36);length=make_file(file,mode);extent=512; }
    for(unsigned i=0;i<9;++i)native_info[i]=0x11220000U+17*i;
#ifndef DX_STANDALONE
    REQUIRE(spx_wine_install_memory(parser_environment,NULL,SPX_WINE_MEMORY_ALL));
    if(source)REQUIRE(install_mds_parse((void (*)(void))replaced_parse));
    SetLastError(0);
#else
    REQUIRE(source);
#endif
    spx_observer o=spx_observe_begin(stdout);spx_observe_object(&o,"mds_parser");spx_observe_array(&o,"parses");
    unsigned calls=mode==31 || mode==32 ? 2 : 1;
    for(unsigned i=0;i<calls;++i) {
        if(i) { if(mode==31)parser_store(file+48,4);else parser_store(file,0); }
        parser_begin(native_info,1);uint32_t result;
#ifndef DX_STANDALONE
        result=((uint32_t (*)(uint32_t *,const unsigned char *,uint32_t))0x401b60)(native_info,file,length);
        if(source)REQUIRE(install_mds_parse_intact() && parser_selected==i+1);
#else
        mds_file input={file};result=fixture_mds_parse(&parser_current->view,&input,length);parser_push();
#endif
        parser_observe(&o,result,file,extent);parser_active=0;
    }
    spx_observe_end(&o);spx_wine_observe(parser_environment,&o,"platform");spx_observe_end(&o);REQUIRE(spx_observe_finish(&o));puts("");
    if(source)REQUIRE(parser_selected==calls);
    parser_dispose_views();spx_wine_destroy(parser_environment);return 0;
}
#ifndef DX_STANDALONE
struct native_startupinfo { int newmode; };
extern int __cdecl __getmainargs(int *,char ***,char ***,int,struct native_startupinfo *);
static void run_case(void) {
    int argc;char **argv,**environment;struct native_startupinfo startup={0};REQUIRE(!__getmainargs(&argc,&argv,&environment,0,&startup));
    int result=main(argc,argv);fflush(NULL);ExitProcess((UINT)result);
}
__declspec(dllexport) void dx_mds_parser_anchor(void) {}
BOOL WINAPI DllMain(HINSTANCE instance,DWORD reason,void *reserved) {
    (void)instance;(void)reserved;return reason!=DLL_PROCESS_ATTACH || ((uintptr_t)GetModuleHandleA(NULL)==0x400000 && install_startup(run_case));
}
#endif
