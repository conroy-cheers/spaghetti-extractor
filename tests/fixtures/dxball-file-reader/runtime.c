/* Application ownership and arguments; shared backend owns every Win32 effect. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "reader-runtime.h"
#include "spx-wine-test.h"
#ifndef DX_STANDALONE
#include <windows.h>
#include "native-image.h"
#endif
#define REQUIRE(x) do { if(!(x)) { fprintf(stderr,"reader boundary line %d: %s\n",__LINE__,#x);exit(3); } } while(0)
static spx_wine_env *environment;
static reader_handle handles[16];
static unsigned handle_count,selected,scenario,allocations,frees,allocation_count;
static unsigned char storage[4][512];
static reader_bytes buffers[4];
static uint32_t live[4],allocation_sizes[4],freed[4];
void reader_enter(void) { ++selected; }
static unsigned identity(reader_bytes *buffer) {
    if(!buffer)return 0;
    for(unsigned i=0;i<4;++i)if(buffer==&buffers[i])return i+1;
    REQUIRE(0);return 0;
}
#ifndef DX_STANDALONE
static reader_bytes *view(void *bytes) {
    if(!bytes)return NULL;
    for(unsigned i=0;i<4;++i)if(bytes==storage[i])return &buffers[i];
    REQUIRE(0);return NULL;
}
#endif
reader_handle *reader_open(void *user,reader_name *name,uint32_t access,uint32_t share,uint32_t disposition,uint32_t attributes) {
    (void)user;uintptr_t h=spx_wine_file_open(environment,name->text,access,share,NULL,disposition,attributes,0);
    if(h==SPX_WINE_INVALID_HANDLE)return NULL;
    REQUIRE(handle_count<16);handles[handle_count].value=h;return &handles[handle_count++];
}
uint32_t reader_size(void *user,reader_handle *handle) { (void)user;return spx_wine_file_size(environment,handle->value,NULL); }
reader_bytes *reader_allocate(void *user,uint32_t size) {
    (void)user;REQUIRE(allocations<4);allocation_sizes[allocations++]=size;
    if(scenario==4 || scenario==16 || size>512)return NULL;
    REQUIRE(allocation_count<3);unsigned i=++allocation_count;live[i]=1;return &buffers[i];
}
uint32_t reader_read(void *user,reader_handle *handle,reader_bytes *buffer,uint32_t size) {
    (void)user;uint32_t count=0;
    return spx_wine_file_read(environment,handle->value,buffer ? buffer->bytes : NULL,size,&count,NULL);
}
void reader_free(void *user,reader_bytes *buffer) {
    (void)user;REQUIRE(frees<4);unsigned id=identity(buffer);freed[frees++]=id;
    if(id) { REQUIRE(live[id-1]);live[id-1]=0;memset(buffer->bytes,0xd1,512); }
}
void reader_close(void *user,reader_handle *handle) { (void)user;(void)spx_wine_file_close(environment,handle->value); }
#ifndef DX_STANDALONE
static void *native_allocate(uint32_t size) { reader_bytes *v=reader_allocate(NULL,size);return v ? v->bytes : NULL; }
static void native_free(void *bytes) { reader_free(NULL,view(bytes)); }
static void *replacement(const char *text,void *supplied,uint32_t allocate) {
    reader_name name={text};reader_bytes *result=fixture_file_read(&name,view(supplied),allocate);return result ? result->bytes : NULL;
}
#endif
static void rule(enum spx_wine_api api,uint32_t flags,uint32_t result,uint32_t value) {
    spx_wine_add_rule(environment,(spx_wine_rule){.api=api,.occurrence=1,.flags=flags,.result=result,.limit=value,.last_error=5});
}
int main(int argc,char **argv) {
    REQUIRE(argc==3);scenario=(unsigned)strtoul(argv[2],NULL,10);REQUIRE(scenario<22);
    for(unsigned i=0;i<4;++i) { buffers[i].bytes=storage[i];memset(storage[i],0x60+i,512); }
    live[0]=1;environment=spx_wine_create(SPX_WINE_CONTROLLED);
    char long_name[257];memset(long_name,'a',256);long_name[256]=0;
    const char *name=scenario==18 ? long_name : "sample.bin";
    char fallback[260];strcpy(fallback,"..\\");strcat(fallback,name);
    unsigned char contents[96];for(unsigned i=0;i<sizeof(contents);++i)contents[i]=(unsigned char)(7*i+3);
    unsigned size=scenario==11 || scenario==12 ? 0 : sizeof(contents);
    if(scenario!=3 && scenario!=20)spx_wine_seed_file(environment,
        scenario==2 || scenario==16 || scenario==17 || scenario==18 ? fallback : name,contents,size);
    if(scenario==5 || scenario==6 || scenario==17)rule(SPX_FILE_READ,SPX_RULE_RETURN|SPX_RULE_ERROR,0,0);
    if(scenario==7 || scenario==8 || scenario==21)rule(SPX_FILE_READ,SPX_RULE_LIMIT,0,scenario==21 ? 0 : 13);
    if(scenario==9)rule(SPX_HANDLE_CLOSE,SPX_RULE_RETURN|SPX_RULE_ERROR,0,0);
    if(scenario==10)rule(SPX_FILE_SIZE,SPX_RULE_RETURN|SPX_RULE_ERROR,UINT32_MAX,0);
    if(scenario==14)rule(SPX_FILE_READ,SPX_RULE_RETURN,7,0);
    if(scenario==15)spx_wine_add_rule(environment,(spx_wine_rule){.api=SPX_FILE_READ,.occurrence=1,
        .flags=SPX_RULE_RETURN|SPX_RULE_ERROR|SPX_RULE_BYTES,.result=0,.last_error=30,.bytes=contents,.byte_count=9});
    if(scenario==20)spx_wine_add_rule(environment,(spx_wine_rule){.api=SPX_FILE_OPEN_A,.flags=SPX_RULE_RETURN|SPX_RULE_ERROR,.result=UINT32_MAX,.last_error=5});
    int source=!strcmp(argv[1],"source");
#ifndef DX_STANDALONE
    REQUIRE(spx_wine_install_files(environment,NULL,SPX_WINE_FILES_ALL));
    REQUIRE(install_reader_allocate((void (*)(void))native_allocate));REQUIRE(install_reader_free((void (*)(void))native_free));
    if(source)REQUIRE(install_file_read((void (*)(void))replacement));
    SetLastError(0);
#else
    REQUIRE(source);
#endif
    unsigned calls=scenario==19 ? 2 : 1;uint32_t answers[2]={0};
    for(unsigned i=0;i<calls;++i) {
        uint32_t allocate=scenario==1 || scenario==6 || scenario==8 || scenario==12 ? 0 : scenario==13 ? UINT32_MAX : 1;
        reader_bytes *supplied=scenario==12 ? NULL : &buffers[0],*result;
#ifndef DX_STANDALONE
        void *raw=((void *(*)(const char *,void *,uint32_t))0x40d9f0)(name,supplied ? supplied->bytes : NULL,allocate);result=view(raw);
        if(source)REQUIRE(install_file_read_intact() && selected==i+1);
#else
        reader_name path={name};result=fixture_file_read(&path,supplied,allocate);
#endif
        answers[i]=identity(result);
    }
    spx_observer o=spx_observe_begin(stdout);spx_observe_object(&o,"reader");
    spx_observe_u32s(&o,"returned",answers,calls);spx_observe_u32s(&o,"live",live,4);
    spx_observe_u32s(&o,"allocations",allocation_sizes,allocations);spx_observe_u32s(&o,"freed",freed,frees);
    spx_observe_array(&o,"buffers");for(unsigned i=0;i<4;++i)spx_observe_bytes(&o,NULL,storage[i],512);spx_observe_end(&o);
    spx_wine_observe(environment,&o,"platform");spx_observe_end(&o);REQUIRE(spx_observe_finish(&o));puts("");spx_wine_destroy(environment);return 0;
}
#ifndef DX_STANDALONE
struct native_startupinfo { int newmode; };
extern int __cdecl __getmainargs(int *,char ***,char ***,int,struct native_startupinfo *);
static void run_case(void) {
    int argc;char **argv,**environment;struct native_startupinfo startup={0};REQUIRE(!__getmainargs(&argc,&argv,&environment,0,&startup));
    int result=main(argc,argv);fflush(NULL);ExitProcess((UINT)result);
}
__declspec(dllexport) void dx_reader_anchor(void) {}
BOOL WINAPI DllMain(HINSTANCE instance,DWORD reason,void *reserved) {
    (void)instance;(void)reserved;return reason!=DLL_PROCESS_ATTACH || ((uintptr_t)GetModuleHandleA(NULL)==0x400000 && install_startup(run_case));
}
#endif
