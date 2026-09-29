/* A separate file consumer, with SDK imports or portable platform bindings. */
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "spx-wine-test.h"
#ifdef _WIN32
#include <windows.h>
#endif
#define CHECK(x) do { if(!(x)) { fprintf(stderr,"file consumer line %d\n",__LINE__);return 42; } } while(0)
static spx_wine_env *environment;
static uintptr_t callback_handle;
static unsigned callback_count,use_security;
#if defined(_WIN32) && !defined(USE_BINDING)
static SECURITY_ATTRIBUTES security={sizeof(SECURITY_ATTRIBUTES),NULL,TRUE};
#define OPEN(p) ((uintptr_t)CreateFileA(p,GENERIC_READ,FILE_SHARE_READ,use_security ? &security : NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL))
#define SIZE(h,p) GetFileSize((HANDLE)(h),(LPDWORD)(p))
#define READ(h,p,n,c,o) ReadFile((HANDLE)(h),p,n,(LPDWORD)(c),o)
#define CLOSE(h) CloseHandle((HANDLE)(h))
#define FILE_ERROR() GetLastError()
#else
static spx_wine_file_security security={12,NULL,1};
#define OPEN(p) spx_wine_file_open(environment,p,0x80000000,1,use_security ? &security : NULL,3,0x80,0)
#define SIZE(h,p) spx_wine_file_size(environment,h,p)
#define READ(h,p,n,c,o) spx_wine_file_read(environment,h,p,n,c,o)
#define CLOSE(h) spx_wine_file_close(environment,h)
#define FILE_ERROR() spx_wine_file_last_error(environment)
#endif
static void callback(void *context,uint32_t token) {
    (void)context;if(token!=5 || SIZE(callback_handle,NULL)!=12)spx_wine_unavailable("file consumer callback");++callback_count;
}
int main(int argc,char **argv) {
    const char *mode=argc>1 ? argv[1] : "controlled";int native=!strncmp(mode,"native",6),defect=!strcmp(mode,"defect");
    use_security=strstr(mode,"security")!=NULL;
    environment=spx_wine_create(native ? SPX_WINE_NATIVE : SPX_WINE_CONTROLLED);
    static const unsigned char content[]={0,1,2,3,4,5,6,7,8,9,10,11},patch[]={0x88,0x99};
    if(!strcmp(mode,"incoming") || !strcmp(mode,"native-incoming") || strstr(mode,"unbound")) {
        /* Distinct candidate input values receive the same declared identities. */
        uintptr_t input=111,other=222;
        if(!native)spx_wine_seed_file(environment,"file.bin",content,sizeof(content));
#ifdef _WIN32
        if(native) {
            input=(uintptr_t)CreateFileA("file.bin",GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);
            CHECK(input!=SPX_WINE_INVALID_HANDLE);
            other=(uintptr_t)CreateSemaphoreA(NULL,1,1,NULL);CHECK(other);
        }
#ifdef USE_BINDING
        else { input=333;other=444; }
#endif
#endif
        spx_wine_bind_handle(environment,input,1,"file.bin",native ? 0 : 2);
        if(!strstr(mode,"unbound"))spx_wine_bind_handle(environment,other,2,NULL,0);
#ifdef _WIN32
        CHECK(spx_wine_install_files(environment,NULL,SPX_WINE_FILES_ALL|(!strcmp(mode,"native-unbound") ? SPX_WINE_FILES_NATIVE_UNBOUND_CLOSE : 0)));
        if(native)CHECK(SetFilePointer((HANDLE)input,2,NULL,FILE_BEGIN)==2);
        SetLastError(0);
#endif
        unsigned char bytes[8];memset(bytes,0x88,8);uint32_t count=0;
        CHECK(READ(input,bytes,3,&count,NULL) && count==3 && bytes[0]==2 && bytes[2]==4 && bytes[3]==0x88);
        CHECK(CLOSE(input) && CLOSE(other));
        spx_observer out=spx_observe_begin(stdout);spx_wine_observe(environment,&out,"platform");
        CHECK(spx_observe_finish(&out));puts("");spx_wine_destroy(environment);return 0;
    }
    if(!native) {
        spx_wine_seed_file(environment,"file.bin",content,sizeof(content));
        spx_wine_add_rule(environment,(spx_wine_rule){.api=SPX_FILE_READ,.occurrence=1,.flags=SPX_RULE_LIMIT|SPX_RULE_CALLBACK,.limit=3,.callback=5});
        spx_wine_add_rule(environment,(spx_wine_rule){.api=SPX_FILE_READ,.occurrence=2,.flags=SPX_RULE_RETURN|SPX_RULE_ERROR|SPX_RULE_BYTES|SPX_RULE_WORD,
            .result=0,.last_error=1234,.bytes=patch,.byte_count=2,.mask=255,.value=2});
        spx_wine_add_rule(environment,(spx_wine_rule){.api=SPX_FILE_READ,.occurrence=3,.flags=SPX_RULE_RETURN|SPX_RULE_NO_WRITE|SPX_RULE_ERROR,.last_error=31});
        spx_wine_add_rule(environment,(spx_wine_rule){.api=SPX_FILE_SIZE,.occurrence=3,.flags=SPX_RULE_RETURN|SPX_RULE_WORD|SPX_RULE_ERROR,
            .result=UINT32_MAX,.value=0x12,.mask=255,.last_error=5});
        spx_wine_add_rule(environment,(spx_wine_rule){.api=SPX_HANDLE_CLOSE,.occurrence=1,.flags=SPX_RULE_RETURN|SPX_RULE_ERROR,.result=0,.last_error=5});
    }
    spx_wine_set_hooks(environment,(spx_wine_hooks){.callback=callback});
#ifdef _WIN32
    /* Preserve these imports in the binding candidate as well. */
    if(argc==99) { HANDLE h=CreateFileA("file.bin",GENERIC_READ,1,NULL,3,0x80,NULL);DWORD n=0;char b[1];GetFileSize(h,NULL);ReadFile(h,b,1,&n,NULL);CloseHandle(h); }
    CHECK(spx_wine_install_files(environment,NULL,SPX_WINE_FILES_ALL));SetLastError(0);
#endif
    uintptr_t h=OPEN("file.bin");CHECK(h!=SPX_WINE_INVALID_HANDLE);callback_handle=h;
    uint32_t high=0xaabbccdd;CHECK(SIZE(h,&high)==12 && !high);
    if(!strcmp(mode,"unsupported")) { uint32_t count=0;unsigned char b[1];READ(h,b,1,&count,(void *)(uintptr_t)1);return 43; }
    unsigned char first[16],second[16],third[16],tail[16];memset(first,0x55,16);memset(second,0x66,16);memset(third,0x77,16);memset(tail,0x44,16);
    uint32_t count=0x11223344;CHECK(READ(h,first,defect ? 7 : 8,&count,NULL));CHECK(count==(native ? 8U : 3U));
    uint32_t count2=0xaabbccdd,r2=READ(h,second,8,&count2,NULL),error2=FILE_ERROR();
    CHECK(native ? r2 && count2==4 : !r2 && count2==0xaabbcc02 && error2==1234);
    uint32_t count3=0x13572468,r3=READ(h,third,8,&count3,NULL),error3=FILE_ERROR();
    CHECK(native ? r3 && count3==0 : !r3 && count3==0x13572468 && error3==31);
    if(!native) { high=0xaabbccdd;CHECK(SIZE(h,&high)==UINT32_MAX && high==0xaabbcc12 && FILE_ERROR()==5); }
    uint32_t tail_count=0;CHECK(READ(h,tail,16,&tail_count,NULL));CHECK(tail_count==(native ? 0U : 7U));
    if(!native)CHECK(!CLOSE(h) && FILE_ERROR()==5);
    uint32_t original_id=spx_wine_file_identity(environment,h);
    if(strcmp(mode,"leak")) {
        CHECK(CLOSE(h));uint32_t expired_count=99;CHECK(!READ(h,tail,1,&expired_count,NULL) && expired_count==0 && FILE_ERROR()==6);
    }
    uintptr_t leaked=OPEN("file.bin");CHECK(leaked!=SPX_WINE_INVALID_HANDLE && spx_wine_file_identity(environment,leaked)!=original_id);
    unsigned char large[1024];memset(large,0xaa,sizeof(large));uint32_t large_count=0;
    CHECK(READ(leaked,large,sizeof(large),&large_count,NULL) && large_count==12 && large[11]==11 && large[12]==0xaa);
    CHECK(OPEN("missing.bin")==SPX_WINE_INVALID_HANDLE && FILE_ERROR()==2);
    CHECK(callback_count==(native ? 0U : 1U));
    spx_observer out=spx_observe_begin(stdout);spx_observe_bytes(&out,"first",first,16);spx_observe_bytes(&out,"second",second,16);
    spx_observe_bytes(&out,"third",third,16);spx_observe_bytes(&out,"tail",tail,16);spx_wine_observe(environment,&out,"platform");
    CHECK(spx_observe_finish(&out));puts("");spx_wine_destroy(environment);return 0;
}
