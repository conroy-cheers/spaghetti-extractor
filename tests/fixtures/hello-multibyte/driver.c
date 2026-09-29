#include "multibyte-runtime.h"
#include <windows.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include "pe32-import-hook.h"
#include "pe32-process-observer.h"

static unsigned char *image;
static uint32_t (__cdecl *decode32)(uint32_t *,const unsigned char *,uint32_t,uint32_t *);
static uint32_t (__cdecl *decode16)(uint16_t *,const unsigned char *,uint32_t,uint32_t *);
static uint32_t (__cdecl *initial)(uint32_t *);
static void (__cdecl *reset)(uint32_t *);
static void require(int condition,const char *message) {
    if(!condition){fprintf(stderr,"multibyte driver: %s\n",message);exit(2);}
}
static uint32_t load(const void *p) {uint32_t value;memcpy(&value,p,4);return value;}
static void hex(const unsigned char *p,unsigned n) {
    putchar('"');for(unsigned i=0;i<n;++i)printf("%02x",p[i]);putchar('"');
}
static unsigned sample(unsigned which,unsigned char *data) {
    static const char *samples[]={"", "A", "abc", "\xc2\x80", "\xc3\xa9", "\xdf\xbf", "\xe0\xa0\x80", "\xed\x9f\xbf",
        "\xee\x80\x80", "\xef\xbf\xbf", "\xf0\x90\x80\x80", "\xf0\x9f\x98\x80", "\xf4\x8f\xbf\xbf",
        "\x80", "\xc0\x80", "\xc1\xbf", "\xe0\x9f\xbf", "\xed\xa0\x80", "\xf0\x8f\xbf\xbf", "\xf4\x90\x80\x80",
        "\xf5\x80\x80\x80", "\xff", "\xc3", "\xe2\x80", "\xf0\x9f\x98", "\xc3\x28", "\xe2\x80\x41", "\xf0\x9f\x98\x41",
        "\x82\xa0", "\x81\x5c", "\x82", "a\xc3\xa9\xf0\x9f\x98\x80"};
    if(which<32){unsigned n=(unsigned)strlen(samples[which]);memcpy(data,samples[which],n+1);return n+1;}
    if(which==32){memcpy(data,"a\0b\0",4);return 4;}
    for(unsigned i=0;i<8;++i)data[i]=(unsigned char)(which*73U+i*41U);
    return 8;
}
static void snapshot(uint32_t result,uint32_t out32,uint16_t out16,uint32_t state[3],const unsigned char *bytes) {
    printf("[%u,%d,%u,%u,%u,%u,%u,%u,%u,",result,errno,out32,out16,state[0],state[1],state[2],
        load(image+0x30314),load(image+0x30318));hex(bytes,32);putchar(']');
}
static spx_fixture_import_hook abort_hook;
static uint32_t fatal_state,fatal_output;
static void observe_abort(void) {
    printf("{\"output\":%u,\"state\":%u,\"errno\":%d}\n",fatal_output,fatal_state,errno);
    require(fflush(stdout)==0,"flush pre-abort observation");
    ((void (*)(void))(uintptr_t)abort_hook.original)();
    require(0,"native abort returned");
}
static void bytes_json(const unsigned char *data,DWORD size) {
    putchar('[');for(DWORD i=0;i<size;++i)printf("%s%u",i?",":"",data[i]);putchar(']');
}
static int terminal(int source,int child,unsigned output_mode) {
    require(output_mode<3,"declared terminal case");
    if(child) {
        SetErrorMode(SEM_FAILCRITICALERRORS|SEM_NOGPFAULTERRORBOX);
        image=(void *)LoadLibraryA("hello-routines.dll");require(image!=NULL,"load terminal image");
        fixture_multibyte_environment(image,2);
        if(source)fixture_multibyte_install(image);
        require(spx_fixture_redirect_import(&abort_hook,"hello-routines.dll","msvcrt.dll","abort",
            (void (*)(void))observe_abort),"observe and forward actual abort");
        decode32=(void *)(image+0x6df3);fatal_state=0x00004101;fatal_output=0xa5a5a5a5;errno=97;
        uint32_t result=decode32(output_mode==1?NULL:output_mode==2?&fatal_state:&fatal_output,
            (const unsigned char *)"B",1,&fatal_state);
        printf("{\"returned\":%u}\n",result);return 0;
    }
    wchar_t executable[32768],command[32768];
    DWORD length=GetModuleFileNameW(NULL,executable,32768);
    require(length && length<32768,"terminal executable path");
    require(swprintf(command,32768,L"\"%ls\" %ls terminal-child %u",executable,
        source?L"source":L"original",output_mode)>0,"terminal child command");
    spx_fixture_process_result result;
    require(spx_fixture_observe_process(executable,command,10000,&result),"complete child observation");
    const char failure[]="multibyte ";
    require(result.err_size<sizeof(failure)-1 || memcmp(result.err,failure,sizeof(failure)-1),"child fixture failed");
    printf("{\"context\":2,\"sequences\":[],\"invalid_state\":[],\"terminal\":{\"exit_code\":%lu,\"stdout\":",result.exit_code);
    bytes_json(result.out,result.out_size);printf(",\"stderr\":");bytes_json(result.err,result.err_size);printf("}}\n");return 0;
}
int main(int argc,char **argv) {
    if(argc==4 && (!strcmp(argv[1],"original") || !strcmp(argv[1],"source")) &&
        (!strcmp(argv[2],"terminal") || !strcmp(argv[2],"terminal-child")))
        return terminal(!strcmp(argv[1],"source"),!strcmp(argv[2],"terminal-child"),(unsigned)strtoul(argv[3],0,10));
    if(argc!=5 || (strcmp(argv[1],"original") && strcmp(argv[1],"source")))return 2;
    unsigned mode=(unsigned)strtoul(argv[2],0,10),operation=(unsigned)strtoul(argv[3],0,10),chunk=(unsigned)strtoul(argv[4],0,10);
    require(mode<3 && operation<2 && chunk>=1 && chunk<=8,"declared case");
    int source=!strcmp(argv[1],"source");
    image=(void *)LoadLibraryA("hello-routines.dll");require(image!=NULL,"load pinned image");
    fixture_multibyte_environment(image,mode);
    if(source)fixture_multibyte_install(image);
    decode32=(void *)(image+0x6df3);decode16=(void *)(image+0x7214);
    initial=(void *)(image+0x7318);reset=(void *)(image+0x2b28);
    printf("{\"context\":%u,\"sequences\":[",mode);
    for(unsigned which=0;which<48;++which)for(unsigned transport=0;transport<6;++transport) {
        uint32_t input_words[8],state[3]={0x13572468,0,0xabcdef91},out32=0xa5a5a5a5;
        uint16_t out16=0x5a5a;unsigned char *bytes=(void *)input_words;
        memset(bytes,0xda,32);unsigned size=sample(which,bytes);
        memset(image+0x30314,0,8);
        uint32_t *selected=transport==2 || transport==3?NULL:state+1;
        uint32_t *p32=transport==1 || transport==3?NULL:transport==4?state+1:transport==5?input_words:&out32;
        uint16_t *p16=transport==1 || transport==3?NULL:&out16;
        if(which || transport)putchar(',');
        printf("{\"input\":%u,\"transport\":%u,\"steps\":[",which,transport);
        errno=97;
        uint32_t zero=operation?decode16(p16,bytes,0,selected):decode32(p32,bytes,0,selected);
        snapshot(zero,out32,out16,state,bytes);
        for(unsigned offset=0;offset<size;) {
            unsigned n=size-offset;if(n>chunk)n=chunk;
            uint32_t result=operation?decode16(p16,bytes+offset,n,selected):decode32(p32,bytes+offset,n,selected);
            putchar(',');snapshot(result,out32,out16,state,bytes);
            unsigned consumed=result==UINT32_MAX?1:result==UINT32_MAX-1U?n:result?result:1;
            require(consumed<=n,"bounded source consumption");offset+=consumed;
        }
        uint32_t result=operation?decode16(p16,NULL,7,selected):decode32(p32,NULL,7,selected);
        putchar(',');snapshot(result,out32,out16,state,bytes);
        printf("],\"initial\":[%u,%u]",initial(selected),initial(NULL));
        reset(state+1);printf(",\"reset\":[%u,%u,%u]}",state[0],state[1],state[2]);
    }
    printf("],\"invalid_state\":[");
    if(mode==2 && !operation) {
        const unsigned counts[]={4,7,127,128,255};
        for(unsigned i=0;i<5;++i)for(unsigned n=0;n<2;++n) {
            uint32_t state=0xdafec400U+counts[i],output=0xa5a5a5a5;errno=97;
            uint32_t result=decode32(&output,(const unsigned char *)"A",n,&state);
            printf("%s[%u,%u,%u,%d]",i||n?",":"",result,output,state,errno);
        }
    }
    printf("],\"terminal\":null}\n");fixture_multibyte_finish(image,source);
    require(FreeLibrary((HMODULE)image),"unload image");return 0;
}
