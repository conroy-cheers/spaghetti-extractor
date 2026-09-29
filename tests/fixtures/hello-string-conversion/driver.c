#include "string-runtime.h"
#include "pe32-import-hook.h"
#include "pe32-process-observer.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <wchar.h>

static unsigned char *image;
static uint32_t (*convert)(uint16_t *,const unsigned char **,uint32_t,void *);
static uint16_t input_words[64],output_words[66];
static uint32_t state[3];
static const unsigned char *cursor;
static void require(int okay,const char *message) {
    if (!okay) {fprintf(stderr,"string driver: %s\n",message);exit(2);}
}
static uint32_t load(const void *p) {uint32_t v;memcpy(&v,p,4);return v;}
static void snapshot(uint32_t result) {
    const unsigned char *bytes=(void *)input_words;
    printf("{\"result\":%u,\"errno\":%d,\"cursor\":%d,\"state\":[%u,%u,%u,%u],\"input\":\"",
        result,errno,cursor ? (int)(cursor-bytes) : -1,state[0],state[1],state[2],load(image+0x30300));
    for (unsigned i=0;i<sizeof(input_words);++i) printf("%02x",bytes[i]);
    printf("\",\"output\":[");
    for (unsigned i=0;i<66;++i) printf("%s%u",i ? "," : "",output_words[i]);
    printf("],\"interactions\":");fixture_string_observe();printf("}");
}
static void reset(unsigned sample) {
    static const unsigned char *const retained[]={
        (const unsigned char *)"",(const unsigned char *)"A",(const unsigned char *)"abcdef",
        (const unsigned char *)"a\0b",(const unsigned char *)"\x82\xa0" "b",
        (const unsigned char *)"\x82",(const unsigned char *)"a\xfd" "b",(const unsigned char *)"\xc3\xa9"};
    memset(input_words,0xda,sizeof(input_words));
    unsigned char *bytes=(void *)input_words;
    if (sample<8) memcpy(bytes,retained[sample],strlen((const char *)retained[sample])+1);
    else {
        unsigned count=(sample-8)*7+1,seed=sample*917U;
        for (unsigned i=0;i<count;++i) {seed=seed*1664525U+1013904223U;bytes[i]=(unsigned char)('a'+seed%26);}
        bytes[count]=0;
    }
    for (unsigned i=0;i<66;++i) output_words[i]=0x5a5a;
    state[0]=0x13572468;state[1]=0;state[2]=0xabcdef91;
    memset(image+0x30300,0,4);cursor=bytes;errno=97;
}
static spx_fixture_import_hook abort_hook;
static void observe_abort(void) {
    snapshot(12345);putchar('\n');require(fflush(stdout)==0,"flush abort state");
    ((void (*)(void))(uintptr_t)abort_hook.original)();require(0,"abort returned");
}
static void array(const unsigned char *data,DWORD size) {
    putchar('[');for (DWORD i=0;i<size;++i) printf("%s%u",i ? "," : "",data[i]);putchar(']');
}
int main(int argc,char **argv) {
    if (argc!=4 || (strcmp(argv[1],"original") && strcmp(argv[1],"source"))) return 2;
    int source=!strcmp(argv[1],"source");unsigned transport=(unsigned)strtoul(argv[3],0,10);
    require(transport<3,"declared transport");
    if (!strcmp(argv[2],"terminal")) {
        wchar_t executable[32768],command[32768];
        DWORD length=GetModuleFileNameW(NULL,executable,32768);
        require(length && length<32768,"child executable");
        require(swprintf(command,32768,L"\"%ls\" %ls child %u",executable,source ? L"source" : L"original",transport)>0,"child command");
        spx_fixture_process_result result;
        require(spx_fixture_observe_process(executable,command,10000,&result),"complete terminal observation");
        require(result.exit_code==3 && result.out_size && !result.err_size,"actual CRT abort, not adapter failure");
        printf("{\"sequences\":[],\"terminal\":{\"exit\":%lu,\"stdout\":",result.exit_code);
        array(result.out,result.out_size);printf(",\"stderr\":");array(result.err,result.err_size);printf("}}\n");return 0;
    }
    int child=!strcmp(argv[2],"child");
    unsigned mode=child ? 2 : (unsigned)strtoul(argv[2],0,10);
    image=(void *)LoadLibraryA("hello-routines.dll");require(image!=NULL,"load pinned image");
    fixture_string_initialize(image,source,mode);convert=(void *)(image+0x29a4);
    if (child) {
        SetErrorMode(SEM_FAILCRITICALERRORS|SEM_NOGPFAULTERRORBOX);
        require(spx_fixture_redirect_import(&abort_hook,"hello-routines.dll","msvcrt.dll","abort",
            (void (*)(void))observe_abort),"observe actual abort");
        reset(0);((unsigned char *)input_words)[0]=0xfe;((unsigned char *)input_words)[1]=0;
        convert(transport==0 ? NULL : output_words+1,&cursor,8,transport==2 ? NULL : state+1);
        require(0,"incomplete service result must abort");
    }
    printf("{\"sequences\":[");unsigned sequence=0;
    const unsigned limits[]={0,1,2,8};
    for (unsigned sample=0;sample<16;++sample) for (unsigned storage=0;storage<3;++storage)
    for (unsigned index=0;index<4;++index) {
        reset(sample);void *selected=storage==0 ? (void *)(state+1) : storage==1 ? NULL : image+0x30300;
        uint16_t *output=transport==0 ? NULL : transport==1 ? output_words+1 : input_words;
        if (sequence++) putchar(',');
        printf("[");
        uint32_t result=convert(output,&cursor,limits[index],selected);snapshot(result);
        if (cursor && result!=UINT32_MAX) {
            printf(",");result=convert(output,&cursor,8,selected);snapshot(result);
        }
        printf("]");
    }
    printf("],\"terminal\":null}\n");
    require(!source || fixture_string_calls()>0,"selected C executed");
    require(FreeLibrary((HMODULE)image),"unload image");return 0;
}
