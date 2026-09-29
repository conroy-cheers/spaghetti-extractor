#include "portable-component-implementation.h"
#include "multibyte-objects.h"
#include "multibyte-runtime.h"
#include "multibyte-image.h"
#include "pe32-entry-hook.h"
#include <locale.h>
#include <stdio.h>
#include <stdlib.h>

typedef struct spx_opaque_mb_bytes_v5 Bytes;
typedef struct spx_opaque_mb_state_v5 State;
typedef struct spx_opaque_mb_word16_v5 Word16;
typedef struct spx_opaque_mb_word32_v5 Word32;
struct Environment { unsigned char *image; Bytes charset; };
static void require(int condition,const char *message) {
    if(!condition){fprintf(stderr,"multibyte fixture: %s\n",message);exit(2);}
}
static void *word(unsigned char *image,uint32_t rva) {
    uint32_t value;memcpy(&value,image+rva,4);return (void *)(uintptr_t)value;
}
static Bytes *charset(void *opaque) {
    struct Environment *e=opaque;const unsigned char *(*call)(void)=(void *)(e->image+0x693c);
    e->charset.data=call();return &e->charset;
}
static uint32_t lower_decode16(void *opaque,Word16 *output,Bytes *input,uint32_t size,State *state) {
    struct Environment *e=opaque;
    uint32_t (*call)(uint16_t *,const unsigned char *,uint32_t,void *)=(void *)(e->image+0x13eb0);
    return call(output?output->value:0,input?input->data:0,size,state?state->data:0);
}
static void set_errno(void *opaque,uint32_t number) {
    struct Environment *e=opaque;int *(*call)(void)=word(e->image,0x321e4);*call()=(int)number;
}
static void invalid_state(void *opaque) {
    struct Environment *e=opaque;void (*call)(void)=word(e->image,0x32204);call();
}
static uint32_t invoke(unsigned char *image,unsigned operation,void *output,
                       const unsigned char *input,uint32_t size,uint32_t *state) {
    _Static_assert(sizeof(void *)==4,"reviewed original PE32 ABI");
    struct Environment environment={.image=image};
    State implicit32={image+0x30314},implicit16={image+0x30318},explicit_state={(void *)state};
    Bytes argument={input};Word16 result16={output};Word32 result32={output};
    const spx_multibyte_conversion_services_v5 services={.context=&environment,.charset=charset,
        .lower_decode16=lower_decode16,.set_errno=set_errno,.invalid_state=invalid_state};
    spx_multibyte_conversion_context_v5 context={.services=&services,
        .state={.implicit32=&implicit32,.implicit16=&implicit16}};
    State *selected=state?&explicit_state:0;
    switch(operation) {
    case 0:return multibyte_decode32(&context,output?&result32:0,input?&argument:0,size,selected);
    case 1:return multibyte_decode16(&context,output?&result16:0,input?&argument:0,size,selected);
    case 2:return multibyte_initial(&context,selected);
    case 3:multibyte_reset(&context,selected);return 0;
    default:abort();
    }
}
uint32_t fixture_multibyte_decode32(unsigned char *image,uint32_t *out,const unsigned char *in,uint32_t n,uint32_t *state) {
    return invoke(image,0,out,in,n,state);
}
uint32_t fixture_multibyte_decode16(unsigned char *image,uint16_t *out,const unsigned char *in,uint32_t n,uint32_t *state) {
    return invoke(image,1,out,in,n,state);
}
static unsigned char *selected_image;
static unsigned counts[4];
void fixture_multibyte_counts(uint32_t out[4]) {memcpy(out,counts,sizeof(counts));}
static spx_fixture_entry_hook hooks[4],charset_hook,width_hook;
static uint32_t hooked32(uint32_t *out,const unsigned char *in,uint32_t n,uint32_t *state) {
    ++counts[0];return fixture_multibyte_decode32(selected_image,out,in,n,state);
}
static uint32_t hooked16(uint16_t *out,const unsigned char *in,uint32_t n,uint32_t *state) {
    ++counts[1];return fixture_multibyte_decode16(selected_image,out,in,n,state);
}
static uint32_t hooked_initial(uint32_t *state) {++counts[2];return invoke(selected_image,2,0,0,0,state);}
static void hooked_reset(uint32_t *state) {++counts[3];(void)invoke(selected_image,3,0,0,0,state);}
static const uint32_t starts[]={0x6df3,0x7214,0x7318,0x2b28};
static const uint32_t ends[]={0x7211,0x7315,0x7331,0x2b35};
static const unsigned char *prefixes[]={mb_decode32_prefix,mb_decode16_prefix,mb_initial_prefix,mb_reset_prefix};
static void (*const replacements[])(void)={(void (*)(void))hooked32,(void (*)(void))hooked16,
    (void (*)(void))hooked_initial,(void (*)(void))hooked_reset};
void fixture_multibyte_install(unsigned char *image) {
    require(!selected_image,"single reviewed image");selected_image=image;
    for(unsigned i=0;i<4;++i)
        require(spx_fixture_redirect_address_body(&hooks[i],image+starts[i],prefixes[i],ends[i]-starts[i],replacements[i]),"replace complete conversion body");
    DWORD old,ignored;
    require(VirtualProtect(image+0x14658,5,PAGE_EXECUTE_READWRITE,&old),"cold protection");
    memset(image+0x14658,0xcc,5);
    require(VirtualProtect(image+0x14658,5,old,&ignored) && FlushInstructionCache(GetCurrentProcess(),image+0x14658,5),"remove cold conversion body");
}
static const unsigned char *controlled_charset(void) {return (const unsigned char *)"UTF-8";}
static uint32_t controlled_width(void) {return 4;}
void fixture_multibyte_environment(unsigned char *image,unsigned mode) {
    require(mode<3,"reviewed locale context");
    require(setlocale(LC_ALL,mode==1?"Japanese_Japan.932":"C")!=NULL,"requested locale available");
    if(mode==2) {
        require(spx_fixture_redirect_address_body(&charset_hook,image+0x693c,mb_charset_prefix,5,
            (void (*)(void))controlled_charset),"controlled UTF-8 charset service");
        require(spx_fixture_redirect_address_body(&width_hook,image+0x141e0,mb_width_prefix,5,
            (void (*)(void))controlled_width),"controlled UTF-8 width service");
    }
}
void fixture_multibyte_finish(unsigned char *image,int source) {
    if(source) {
        for(unsigned i=0;i<4;++i) {
            require(hooks[i].entry==image+starts[i] && hooks[i].entry[0]==0xe9,"selected conversion entry");
            uint32_t displacement;memcpy(&displacement,hooks[i].entry+1,4);
            require((uint32_t)(uintptr_t)(hooks[i].entry+5)+displacement==(uint32_t)(uintptr_t)replacements[i],"conversion replacement jump");
            for(size_t j=5;j<hooks[i].length;++j)require(hooks[i].entry[j]==0xcc,"conversion body remains removed");
        }
        for(unsigned i=0x14658;i<0x1465d;++i)require(image[i]==0xcc,"conversion cold body remains removed");
    }
    fprintf(stderr,"HELLO_MULTIBYTE_C %u %u %u %u\n",counts[0],counts[1],counts[2],counts[3]);
}
