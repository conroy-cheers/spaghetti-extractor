/* Independent secondary-buffer caller: no application addresses or layouts. */
#define CINTERFACE 1
#define COBJMACROS 1
#include <windows.h>
#include <dsound.h>
#include <stdio.h>
#include <string.h>
#include "spx-wine-test.h"
#define CHECK(x) do { if(!(x)) { fprintf(stderr,"consumer line %d\n",__LINE__);return 42; } } while(0)
static spx_wine_env *environment;
static unsigned callbacks;
static IDirectSoundBuffer *callback_buffer;
static void callback(void *context,uint32_t token) {
    (void)context;if(token!=17)spx_wine_unavailable("unbound application callback");++callbacks;
    DWORD frequency=0;
    if(IDirectSoundBuffer_GetFrequency(callback_buffer,&frequency) || frequency!=16000)
        spx_wine_unavailable("application callback query");
}
#ifdef USE_BINDING
static uint32_t invoke(enum spx_wine_api api,void *receiver,void *output,const void *input,uint32_t a,uint32_t b,uint32_t c) {
    spx_wine_call call={0};call.api=api;call.receiver=receiver;call.output=output;call.input=input;
    call.arguments[0]=a;call.arguments[1]=b;call.arguments[2]=c;call.argument_count=3;
    return spx_wine_candidate_call(environment,call);
}
#define CREATE(d) invoke(SPX_DS_CREATE,NULL,d,NULL,0,0,0)
#define METHOD(api,obj,value) invoke(api,obj,NULL,NULL,value,0,0)
#else
#define CREATE(d) DirectSoundCreate(NULL,d,NULL)
#endif
int main(int argc,char **argv) {
    int native=argc>1 && !strcmp(argv[1],"native");
    int defect=argc>1 && !strcmp(argv[1],"defect");
    unsigned char payload[48],readback[48];memset(payload,0x23,sizeof(payload));
    memset(payload+11,0x38,8);memset(payload+19,0x71,8);
    FILE *file=fopen("payload.bin","wb");CHECK(file && fwrite(payload,1,sizeof(payload),file)==sizeof(payload));CHECK(!fclose(file));
    /* Keep both imports present for either independently compiled candidate. */
    if(argc==99) { IDirectSound *unused=NULL;DirectSoundCreate(NULL,&unused,NULL);MessageBoxA(NULL,"","",0);
        HANDLE h=CreateFileA("",GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,0,NULL);DWORD n;ReadFile(h,readback,48,&n,NULL);CloseHandle(h); }
    environment=spx_wine_create(native ? SPX_WINE_NATIVE : SPX_WINE_CONTROLLED);
    spx_wine_set_hooks(environment,(spx_wine_hooks){.callback=callback});
    if(!native) {
        spx_wine_add_rule(environment,(spx_wine_rule){.api=SPX_DS_STATUS,.occurrence=1,
            .flags=SPX_RULE_WORD|SPX_RULE_RETURN|SPX_RULE_CALLBACK,.result=0x80004005,.mask=0xff,.value=2,.callback=17});
        spx_wine_add_rule(environment,(spx_wine_rule){.api=SPX_DS_STATUS,.occurrence=2,
            .flags=SPX_RULE_NO_WRITE|SPX_RULE_RETURN,.result=0x80004005});
    }
    CHECK(spx_wine_install(environment,NULL,1,1));
    if(!native)spx_wine_seed_file(environment,"payload.bin",payload,sizeof(payload));
    CHECK(spx_wine_install_files(environment,NULL,SPX_WINE_FILES_OPEN|SPX_WINE_FILES_READ|SPX_WINE_FILES_CLOSE));
    SetLastError(0); /* Explicit incoming thread state for the file boundary. */
    uintptr_t file_handle=spx_wine_file_open(environment,"payload.bin",GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,0,0);
    uint32_t read_count=0;CHECK(file_handle!=SPX_WINE_INVALID_HANDLE);
    CHECK(spx_wine_file_read(environment,file_handle,readback,sizeof(readback),&read_count,NULL) && read_count==sizeof(readback));
    CHECK(spx_wine_file_close(environment,file_handle));
    IDirectSound *device=NULL;CHECK(CREATE(&device)==0 && device);
    if(!native) {
        spx_wine_bind_window(environment,111,1);spx_wine_bind_window(environment,222,2);
        uintptr_t chosen=argc>1 && !strcmp(argv[1],"wrong-window") ? 222 : 111;
#ifdef USE_BINDING
        spx_wine_call call={0};call.api=SPX_DS_COOPERATIVE;call.receiver=(void *)device;
        call.window=chosen;call.arguments[0]=1;call.argument_count=1;
        CHECK(spx_wine_candidate_call(environment,call)==0);
#else
        CHECK(IDirectSound_SetCooperativeLevel(device,(HWND)chosen,1)==0);
#endif
    }
    WAVEFORMATEX format={WAVE_FORMAT_PCM,1,22050,44100,2,16,0};
    DSBUFFERDESC desc={0};desc.dwSize=20;desc.dwFlags=DSBCAPS_CTRLVOLUME|DSBCAPS_CTRLPAN|DSBCAPS_CTRLFREQUENCY;
    desc.dwBufferBytes=32;desc.lpwfxFormat=&format;IDirectSoundBuffer *buffer=NULL;
#ifdef USE_BINDING
    spx_wine_buffer_spec spec={20,desc.dwFlags,32,0,&format};
    CHECK(invoke(SPX_DS_CREATE_BUFFER,device,&buffer,&spec,0,0,0)==0);
#else
    CHECK(IDirectSound_CreateSoundBuffer(device,&desc,&buffer,NULL)==0);
#endif
    callback_buffer=buffer;
    if(argc>1 && !strcmp(argv[1],"unsupported")) {
        DSBCAPS caps={0};caps.dwSize=sizeof(caps);IDirectSoundBuffer_GetCaps(buffer,&caps);return 43;
    }
    void *first=NULL,*second=NULL;DWORD first_bytes=0,second_bytes=0;
#ifdef USE_BINDING
    spx_wine_locked parts={0};CHECK(invoke(SPX_DS_LOCK,buffer,&parts,NULL,24,16,0)==0);
    first=parts.first;second=parts.second;first_bytes=parts.first_bytes;second_bytes=parts.second_bytes;
#else
    CHECK(IDirectSoundBuffer_Lock(buffer,24,16,&first,&first_bytes,&second,&second_bytes,0)==0);
#endif
    CHECK(first_bytes+second_bytes==16);memset(first,defect ? 0x39 : 0x38,first_bytes);
    if(second_bytes)memset(second,0x71,second_bytes);
#ifdef USE_BINDING
    CHECK(invoke(SPX_DS_UNLOCK,buffer,NULL,&parts,0,0,0)==0);
    CHECK(METHOD(SPX_DS_FREQUENCY,buffer,16000)==0);
#else
    CHECK(IDirectSoundBuffer_Unlock(buffer,first,first_bytes,second,second_bytes)==0);
    CHECK(IDirectSoundBuffer_SetFrequency(buffer,16000)==0);
#endif
    DWORD value=0xaabbccdd;
    for(unsigned i=0;i<2;++i) {
#ifdef USE_BINDING
        uint32_t result=invoke(SPX_DS_STATUS,buffer,&value,NULL,0,0,0);
#else
        uint32_t result=(uint32_t)IDirectSoundBuffer_GetStatus(buffer,&value);
#endif
        CHECK(native ? result==0 : result==0x80004005 && value==0xaabbcc02);
    }
    static const GUID buffer_iid={0x279afa85,0x4981,0x11ce,{0xa5,0x21,0,0x20,0xaf,0x0b,0xe5,0x60}};
    IDirectSoundBuffer *alias=NULL;
#ifdef USE_BINDING
    CHECK(invoke(SPX_COM_QUERY,buffer,&alias,&buffer_iid,0,0,0)==0 && alias==buffer);
    CHECK(METHOD(SPX_COM_ADDREF,alias,0)>1);
    METHOD(SPX_COM_RELEASE,alias,0);METHOD(SPX_COM_RELEASE,alias,0);
    METHOD(SPX_COM_RELEASE,buffer,0);METHOD(SPX_COM_RELEASE,device,0);
#else
    CHECK(IDirectSoundBuffer_QueryInterface(buffer,&buffer_iid,(void **)&alias)==0 && alias==buffer);
    CHECK(IDirectSoundBuffer_AddRef(alias)>1);
    IDirectSoundBuffer_Release(alias);IDirectSoundBuffer_Release(alias);
    IDirectSoundBuffer_Release(buffer);IDirectSound_Release(device);
#endif
    CHECK(callbacks==(native ? 0U : 1U));
    spx_observer out=spx_observe_begin(stdout);spx_wine_observe(environment,&out,"platform");
    CHECK(spx_observe_finish(&out));puts("");spx_wine_destroy(environment);return 0;
}
