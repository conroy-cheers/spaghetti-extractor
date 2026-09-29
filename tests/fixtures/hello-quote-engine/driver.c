#include "quote-buffer-runtime.h"
#include "comparison-selection.h"
#ifdef SPX_SELECTED_MULTIBYTE_CONVERSION
#define HELLO_QUOTE_MULTIBYTE 1
#include "multibyte-runtime.h"
#else
#define HELLO_QUOTE_MULTIBYTE 0
#endif
#include <windows.h>
#include <errno.h>
#include <locale.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void require(int condition,const char *message) {
    if(!condition){fprintf(stderr,"quote engine fixture: %s (%lu)\n",message,GetLastError());exit(2);}
}
static void hex(const unsigned char *data,unsigned size) {
    putchar('"');for(unsigned i=0;i<size;++i)printf("%02x",data[i]);putchar('"');
}
static unsigned sample(unsigned which,unsigned char *arg) {
    const char *texts[]={"", "simple", "a b", "it's", "a'b$", "\\", "a\\b", "?" "?/", "{", "x{", "#~", "a:b",
        "'\"`[]$%^&*(){}!~|;<=>?", "\a\b\f\n\r\t\v", "left]>right", "0123456789", "\xc3\xa9", "\xf0\x9f\x98\x80",
        "\xe2\x80\x98x\xe2\x80\x99", "\xc3", "\xc3\x28", "\xff\xfe", "\x81\x5c", "\x82\xa0"};
    if(which<sizeof(texts)/sizeof(texts[0])){unsigned n=(unsigned)strlen(texts[which]);memcpy(arg,texts[which],n+1);return n;}
    if(which==24){memcpy(arg,"a\0b\0007",5);arg[5]=0;return 5;}
    unsigned n=which==25?256:which==26?127:63;
    for(unsigned i=0;i<n;++i)arg[i]=(unsigned char)(which==25?i:which==26?(i*73U+13U):'\'');
    arg[n]=0;return n;
}
int main(int argc,char **argv) {
    if(argc!=5 || (strcmp(argv[1],"original") && strcmp(argv[1],"source")))return 2;
    unsigned values[3];
    for(unsigned i=0;i<3;++i){char *end;unsigned long v=strtoul(argv[i+2],&end,10);if(!*argv[i+2] || *end || v>32)return 2;values[i]=(unsigned)v;}
    unsigned style=values[0],flags=values[1],locale=values[2];
    const char *locales[]={"C",".65001","Japanese_Japan.932"};
    require(style<=10 && flags<=7 && locale<(HELLO_QUOTE_MULTIBYTE?4U:3U),"declared case");
    require(setlocale(LC_ALL,locales[locale<3?locale:0])!=NULL,"requested locale is available");
    unsigned char *image=(void *)LoadLibraryA("hello-routines.dll");require(image!=NULL,"load pinned routine image");
#if HELLO_QUOTE_MULTIBYTE
    if(locale==3)fixture_multibyte_environment(image,2);
    if(!strcmp(argv[1],"source"))fixture_multibyte_install(image);
#endif
    uint32_t maximum_address;memcpy(&maximum_address,image+0x200b4,4);
    uint32_t (*maximum)(void)=(void *)(uintptr_t)maximum_address;
    uint32_t (__attribute__((regparm(3))) *original)(unsigned char *,uint32_t,unsigned char *,uint32_t,uint32_t,
        uint32_t,const uint32_t *,unsigned char *,unsigned char *)=(void *)(image+0x36ea);
    unsigned capacities[]={0,1,2,3,7,16,32,128,1024};
    unsigned char argument[320],arena[1056],left[]="<[",right[]="]>";
    printf("{\"mb_cur_max\":%u,\"samples\":[",maximum());
    for(unsigned which=0;which<28;++which)for(unsigned mode=0;mode<4;++mode) {
        memset(argument,0xa5,sizeof(argument));unsigned size=sample(which,argument);
        unsigned capacity=mode<2?capacities[(which+style+flags+mode*3)%9]:16;
        uint32_t mask_storage[16],*mask=mask_storage+4;
        memset(mask_storage,0xda,sizeof(mask_storage));memset(mask,0,32);
        if(mode){mask[':' /32]|=1U<<(':'%32);mask['?' /32]|=1U<<('?'%32);}
        memset(arena,0xa7,sizeof(arena));errno=97;
        uint32_t count=mode==1 && which!=24?UINT32_MAX:size;
        unsigned char *output=mode==2?argument+1:mode==3?(unsigned char *)mask+1:capacity?arena+16:NULL;
        uint32_t result=!strcmp(argv[1],"source")?
            fixture_quote_buffer(image,output,capacity,argument,count,style,flags,mask,left,right):
            original(output,capacity,argument,count,style,flags,mask,left,right);
        if(which || mode)putchar(',');
        printf("{\"input\":%u,\"mode\":%u,\"terminated\":%u,\"capacity\":%u,\"result\":%u,\"errno\":%d,\"buffer\":",
            which,mode,count==UINT32_MAX,capacity,result,errno);
        hex(arena,16+capacity+16);printf(",\"argument\":");hex(argument,sizeof(argument));printf(",\"mask\":[");
        for(unsigned i=0;i<8;++i)printf("%s%u",i?",":"",mask[i]);
        printf("],\"mask_frame\":");hex((unsigned char *)mask_storage,sizeof(mask_storage));printf("}");
    }
    printf("]}\n");
#if HELLO_QUOTE_MULTIBYTE
    fixture_multibyte_finish(image,!strcmp(argv[1],"source"));
#endif
    require(FreeLibrary((HMODULE)image),"unload original routines");return 0;
}
