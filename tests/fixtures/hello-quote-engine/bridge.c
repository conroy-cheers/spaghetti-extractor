#include "portable-component-implementation.h"
#include "quote-buffer-objects.h"
#include "quote-buffer-runtime.h"
#include <string.h>

typedef struct spx_opaque_quote_bytes_v5 Bytes;
typedef struct spx_opaque_quote_conversion_v5 Conversion;
struct Environment { unsigned char *image; Bytes quotes[2]; };
static void *word(struct Environment *e,uint32_t rva) {
    uint32_t value;memcpy(&value,e->image+rva,4);return (void *)(uintptr_t)value;
}
static uint32_t maximum(void *opaque) {
    struct Environment *e=opaque;uint32_t (*call)(void)=word(e,0x200b4);return call();
}
static Bytes *locale_quote(void *opaque,uint32_t right,uint32_t style) {
    struct Environment *e=opaque;
    unsigned char *(__attribute__((regparm(2))) *call)(const char *,uint32_t)=(void *)(e->image+0x367b);
    e->quotes[right].data=call((const char *)(e->image+(right?0x214c2:0x214c4)),style);return &e->quotes[right];
}
static uint32_t byte_printable(void *opaque,uint32_t byte) {
    struct Environment *e=opaque;int (*call)(int)=word(e,0x3223c);return (uint32_t)call((int)byte);
}
static void reset(void *opaque,Conversion *conversion) {
    struct Environment *e=opaque;void (*call)(uint32_t *)=(void *)(e->image+0x2b28);call(&conversion->state);
}
static uint32_t decode(void *opaque,Conversion *conversion,Bytes *argument,uint32_t offset,uint32_t size) {
    struct Environment *e=opaque;
    uint32_t (*call)(uint32_t *,const unsigned char *,uint32_t,uint32_t *)=(void *)(e->image+0x6df3);
    return call(&conversion->character,argument->data+offset,size,&conversion->state);
}
static uint32_t character_printable(void *opaque,uint32_t character) {
    struct Environment *e=opaque;uint32_t (*call)(uint32_t)=(void *)(e->image+0x683c);return call(character);
}
static uint32_t initial(void *opaque,Conversion *conversion) {
    struct Environment *e=opaque;uint32_t (*call)(uint32_t *)=(void *)(e->image+0x7318);return call(&conversion->state);
}
static void invalid(void *opaque) {
    struct Environment *e=opaque;void (*call)(void)=word(e,0x32204);call();
}
uint32_t fixture_quote_buffer(unsigned char *image,unsigned char *output,uint32_t capacity,
    unsigned char *argument,uint32_t size,uint32_t style,uint32_t flags,
    const uint32_t *mask,unsigned char *left,unsigned char *right) {
    _Static_assert(sizeof(void *)==4,"reviewed original PE32 service ABI");
    struct Environment environment={.image=image};
    const spx_quote_buffer_services_v5 services={.context=&environment,.mb_cur_max=maximum,
        .locale_quote=locale_quote,.byte_printable=byte_printable,.conversion_reset=reset,
        .decode=decode,.character_printable=character_printable,.conversion_initial=initial,.invalid_style=invalid};
    spx_quote_buffer_context_v5 context={.services=&services};
    Bytes destination={output},input={argument},open={left},close={right};
    struct spx_opaque_quote_mask_v5 empty_mask={{0}};
    struct spx_opaque_quote_mask_v5 *mask_value=mask?(void *)mask:&empty_mask;
    return quote_buffer(&context,output?&destination:0,capacity,argument?&input:0,size,style,flags,
        mask_value,left?&open:0,right?&close:0);
}
