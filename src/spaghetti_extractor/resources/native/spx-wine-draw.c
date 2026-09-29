/* Candidate-neutral legacy DirectDraw surfaces. Controlled storage is scenario
 * input; native mode forwards the same calls to Wine without a role flag. */
#include "spx-wine-test-internal.h"
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#define CINTERFACE 1
#define COBJMACROS 1
#include <ddraw.h>
#include "pe32-import-hook.h"
#endif

enum { DRAW_BYTES=4194304, DESC_FLAGS=0x000ff9ef };
typedef struct {
    spx_wine_surface_desc spec;
    void *locked_pixels;
    uint32_t locks,width,height,pixel_bytes;
    int32_t pitch;
    spx_wine_rect rectangle;
} draw_surface;
static void require(int yes,const char *why) { if(!yes)spx_wine_unavailable(why); }
static int failed(uint32_t result) { return !!(result&UINT32_C(0x80000000)); }
static int32_t signed_word(uint32_t word) { return (int32_t)(word<0x80000000U ? (int64_t)word : (int64_t)word-4294967296LL); }
static draw_surface *surface(spx_wine_object *o) {
    require(o && o->kind==SPX_WINE_DD_SURFACE,"DirectDraw surface receiver");
    if(!o->surface) { o->surface=calloc(1,sizeof(draw_surface));require(o->surface!=NULL,"surface metadata allocation"); }
    return o->surface;
}
static void bytes(spx_wine_event *v,const void *data,size_t size) {
    require(size<=DRAW_BYTES && (!size || data),"surface observation extent");
    v->data_bytes=size;v->data=size ? malloc(size) : NULL;require(!size || v->data,"surface observation allocation");
    if(size)memcpy(v->data,data,size);
}
static void words(spx_wine_event *v,const uint32_t *values,size_t count) {
    bytes(v,values,count*4);
    for(size_t i=0;i<count;++i)for(unsigned j=0;j<4;++j)v->data[i*4+j]=(unsigned char)(values[i]>>(j*8));
}
static void descriptor(spx_wine_event *v,const spx_wine_surface_desc *d) {
    require(d && d->words[0]==108 && !d->words[9],"legacy surface descriptor transport");
    uint32_t f=d->words[1],w[27]={108,f};require(!(f&~DESC_FLAGS),"surface descriptor flags");
    if(f&2)w[2]=d->words[2];
    if(f&4)w[3]=d->words[3];
    if(f&0x80008)w[4]=d->words[4];
    if(f&0x20)w[5]=d->words[5];
    if(f&0x60040)w[6]=d->words[6];
    if(f&0x80)w[7]=d->words[7];
    if(f&0x800)w[9]=d->pixels!=NULL;
    for(unsigned i=0;i<4;++i)if(f&(0x2000U<<i))memcpy(w+10+2*i,d->words+10+2*i,8);
    if(f&0x1000)memcpy(w+18,d->words+18,32);
    if(f&1)w[26]=d->words[26];
    words(v,w,27);
}
static uint32_t pixel_bytes(const spx_wine_surface_desc *d) {
    uint32_t bits=d->words[21];
    require((d->words[1]&0x1000) && d->words[18]==32 && (d->words[19]&0x40) &&
        !(d->words[19]&~0x61U) && (bits==8 || bits==16 || bits==24 || bits==32),"uncompressed 8/16/24/32-bit RGB surface required");
    return bits/8;
}
static void configure(spx_wine_object *o,const spx_wine_surface_desc *input,const void *initial,uint32_t size) {
    draw_surface *s=surface(o);require(input && input->words[0]==108 && !input->words[9] && !input->pixels,"controlled surface descriptor");
    s->spec=*input;
    require((input->words[1]&0x1007)==0x1007 && !(input->words[1]&~0x100fU),"controlled surface creation fields");
    require(input->words[26]==0x840,"controlled offscreen system-memory surface capabilities");
    uint32_t w=input->words[3],h=input->words[2],b=pixel_bytes(input);
    require(w && h && w<=4096 && h<=4096,"controlled surface dimensions");
    int32_t pitch=input->words[1]&8 ? signed_word(input->words[4]) : (int32_t)((w*b+3)&~3U);
    uint64_t stride=pitch<0 ? -(int64_t)pitch : pitch,total=stride*h;
    require(stride>=w*b && total<=DRAW_BYTES,"controlled surface backing extent");
    require(!initial || size==total,"seeded surface backing size");
    o->size=(uint32_t)total;o->bytes=malloc(o->size);require(o->bytes!=NULL,"controlled surface backing allocation");
    if(initial)memcpy(o->bytes,initial,o->size);else memset(o->bytes,0,o->size);
    s->spec.words[1]|=8;s->spec.words[4]=(uint32_t)pitch;
    s->spec.pixels=o->bytes+(pitch<0 ? (h-1)*stride : 0);
}
spx_wine_object *spx_wine_seed_surface(spx_wine_env *e,uint32_t id,const spx_wine_surface_desc *d,const void *initial,uint32_t size) {
    require(initial && size,"explicit seeded surface bytes");
    spx_wine_object *o=spx_wine_seed(e,id,SPX_WINE_DD_SURFACE,(spx_wine_object_state){.references=1});
    configure(o,d,initial,size);return o;
}
const unsigned char *spx_wine_surface_bytes(spx_wine_object *o,uint32_t *size) {
    require(o && o->owner->mode==SPX_WINE_CONTROLLED && o->kind==SPX_WINE_DD_SURFACE && o->bytes && size,"controlled surface storage observation");
    *size=o->size;return o->bytes;
}
spx_wine_object *spx_wine_bind_surface(spx_wine_env *e,void *native,uint32_t input_identity) {
    require(e && e->mode==SPX_WINE_NATIVE && native && input_identity,"borrowed native surface input binding");
    spx_wine_thread_check(e);
    for(unsigned i=0;i<e->object_count;++i) {
        spx_wine_object *o=&e->objects[i];
        if(o->kind==SPX_WINE_DD_SURFACE && (o->input_identity==input_identity || o->native==native)) {
            require(o->input_identity==input_identity && o->native==native,"conflicting borrowed surface correspondence");return o;
        }
    }
    spx_wine_object *o=spx_wine_new_object(e,SPX_WINE_DD_SURFACE,native);
    o->input_identity=input_identity;o->state.references=0;return o;
}
void spx_wine_draw_validate_rule(const spx_wine_rule *r) {
    int factory=r->api==SPX_DD_CREATE || r->api==SPX_DD_CREATE_SURFACE;
    int output=factory || r->api==SPX_DD_DESCRIBE || r->api==SPX_DD_LOCK;
    require(!(r->flags&~(SPX_RULE_RETURN|SPX_RULE_OBJECT|SPX_RULE_NO_WRITE|SPX_RULE_CALLBACK|SPX_RULE_BYTES)),"DirectDraw scenario flags");
    require(!(r->flags&SPX_RULE_OBJECT) || factory,"DirectDraw publication rule requires a factory");
    require(!(r->flags&SPX_RULE_NO_WRITE) || output,"DirectDraw no-write rule requires output");
    require(!(r->flags&SPX_RULE_BYTES) || (r->api==SPX_DD_DESCRIBE && r->byte_count<=36 && (!r->byte_count || r->bytes)),"descriptor prefix rule covers the scalar prefix before lpSurface");
    require(!(r->flags&SPX_RULE_NO_WRITE) || !(r->flags&(SPX_RULE_OBJECT|SPX_RULE_BYTES)),"conflicting DirectDraw outputs");
}
static spx_wine_rect rectangle(draw_surface *s,const void *input) {
    if(input)return *(const spx_wine_rect *)input;
    return (spx_wine_rect){0,0,(int32_t)s->spec.words[3],(int32_t)s->spec.words[2]};
}
static void admitted_rect(draw_surface *s,spx_wine_rect r) {
    require(r.left>=0 && r.top>=0 && r.right>r.left && r.bottom>r.top &&
        (uint32_t)r.right<=s->spec.words[3] && (uint32_t)r.bottom<=s->spec.words[2],"controlled surface rectangle; invalid regions require an explicit failure schedule");
}
static void output_desc(draw_surface *s,spx_wine_surface_desc *d,int lock,spx_wine_rect r) {
    require(d && d->words[0]==108 && !d->words[9],"surface description output");
    d->words[1]=s->spec.words[1] | (lock ? 0x800 : 0);
    d->words[2]=lock ? (uint32_t)(r.bottom-r.top) : s->spec.words[2];
    d->words[3]=lock ? (uint32_t)(r.right-r.left) : s->spec.words[3];
    d->words[4]=s->spec.words[4];memcpy(d->words+18,s->spec.words+18,32);d->words[26]=s->spec.words[26];
    d->pixels=lock ? (unsigned char *)s->spec.pixels+(int64_t)r.top*signed_word(s->spec.words[4])+(int64_t)r.left*pixel_bytes(&s->spec) : NULL;
}
static uint32_t controlled(spx_wine_env *e,spx_wine_call *c,spx_wine_event *v,const spx_wine_rule *rule) {
    uint32_t result=rule->flags&SPX_RULE_RETURN ? rule->result : 0;
    spx_wine_object *o=c->receiver;
    if(o)require(o->state.references!=0,"controlled expired DirectDraw receiver");
    if(c->api==SPX_DD_CREATE || c->api==SPX_DD_CREATE_SURFACE) {
        if(!(rule->flags&SPX_RULE_NO_WRITE) && (!failed(result) || (rule->flags&SPX_RULE_OBJECT))) {
            enum spx_wine_kind kind=c->api==SPX_DD_CREATE ? SPX_WINE_DD_DEVICE : SPX_WINE_DD_SURFACE;
            spx_wine_object *made=NULL;
            if(rule->flags&SPX_RULE_OBJECT) {
                if(rule->object)made=spx_wine_object_at(e,rule->object);
            } else {
                made=spx_wine_new_object(e,kind,NULL);if(kind==SPX_WINE_DD_SURFACE)configure(made,c->input,NULL,0);
            }
            if(made) {
                require(made->kind==kind,"DirectDraw output interface kind");
                if(rule->references) { made->state.references=rule->references;++made->state.generation; }
            }
            spx_wine_store_object(c->output,made);v->output_object=spx_wine_object_id(made);v->written_mask=UINT32_MAX;
        }
        return result;
    }
    if(c->api==SPX_DD_COOPERATIVE) { require(c->arguments[0]==8,"controlled DDSCL_NORMAL cooperative level");return result; }
    draw_surface *s=surface(o);
    if(c->api==SPX_DD_DESCRIBE && (rule->flags&SPX_RULE_BYTES)) {
        uint32_t *w=((spx_wine_surface_desc *)c->output)->words;
        for(unsigned i=0;i<rule->byte_count;++i) {
            unsigned shift=(i%4)*8;w[i/4]=(w[i/4]&~(0xffU<<shift))|((uint32_t)rule->bytes[i]<<shift);
        }
        memset(v->byte_mask,0xff,rule->byte_count);return result;
    }
    if(failed(result) || (rule->flags&SPX_RULE_NO_WRITE))return result;
    switch(c->api) {
    case SPX_DD_DESCRIBE:output_desc(s,c->output,0,rectangle(s,NULL));break;
    case SPX_DD_LOCK: {
        require(!s->locks,"controlled overlapping surface locks");spx_wine_rect r=rectangle(s,c->input);admitted_rect(s,r);
        output_desc(s,c->output,1,r);break;
    }
    case SPX_DD_UNLOCK:require(s->locks!=0,"controlled surface unlock without a lock");break;
    case SPX_DD_BLT: {
        require(!s->locks,"controlled fill while surface locked");const spx_wine_blt *b=c->input;
        spx_wine_rect r=rectangle(s,b->destination);admitted_rect(s,r);unsigned n=pixel_bytes(&s->spec);
        uint32_t mask=s->spec.words[19]&0x20 ? 0xff : s->spec.words[22]|s->spec.words[23]|s->spec.words[24];
        if(s->spec.words[19]&1)mask|=s->spec.words[25];
        uint32_t color=b->fill_color&mask;
        for(int32_t y=r.top;y<r.bottom;++y)for(int32_t x=r.left;x<r.right;++x) {
            unsigned char *p=(unsigned char *)s->spec.pixels+(int64_t)y*signed_word(s->spec.words[4])+(int64_t)x*n;
            for(unsigned i=0;i<n;++i)p[i]=(unsigned char)(color>>(8*i));
        }
        break;
    }
    default:spx_wine_unavailable("controlled DirectDraw operation");
    }
    if(c->api==SPX_DD_DESCRIBE || c->api==SPX_DD_LOCK) {
        memset(v->byte_mask+4,0xff,16);memset(v->byte_mask+36,0xff,4);memset(v->byte_mask+72,0xff,36);
    }
    return result;
}
#ifdef _WIN32
#include "spx-wine-draw-sdk.h"
#else
void spx_wine_draw_object(spx_wine_object *o) { (void)o; }
int spx_wine_install_draw(spx_wine_env *e,const char *module) { (void)e;(void)module;return 0; }
int spx_wine_uninstall_draw(spx_wine_env *e) { (void)e;return 1; }
uint32_t spx_wine_draw_candidate_call(spx_wine_env *e,spx_wine_call c) { return spx_wine_invoke(e,c); }
static uint32_t native(spx_wine_env *e,spx_wine_call *c,spx_wine_event *v) {
    (void)e;(void)c;(void)v;spx_wine_unavailable("native DirectDraw requires Win32/Wine");return 0;
}
#endif
uint32_t spx_wine_draw_invoke(spx_wine_env *e,spx_wine_call c) {
    require(c.api>=SPX_DD_CREATE && c.api<=SPX_DD_BLT,"DirectDraw call shape");
    spx_wine_object *o=c.receiver;draw_surface *s=NULL;
    require(!o || o->owner==e,"foreign DirectDraw receiver");
    if(c.api!=SPX_DD_CREATE)require(o && o->kind==(c.api<=SPX_DD_CREATE_SURFACE ? SPX_WINE_DD_DEVICE : SPX_WINE_DD_SURFACE),"DirectDraw receiver kind");
    if(c.api>=SPX_DD_DESCRIBE)s=surface(o);
    require(e->event_count<SPX_WINE_EVENTS,"DirectDraw event capacity");
    spx_wine_event *v=&e->events[e->event_count++];v->sequence=e->event_count;v->api=c.api;v->occurrence=++e->calls[c.api];
    v->controlled=e->mode==SPX_WINE_CONTROLLED;v->receiver=spx_wine_object_id(o);v->kind=o ? o->kind : 0;
    if(o) { v->references_before=o->state.references;v->generation=o->state.generation;v->input_identity=o->input_identity; }
    if(s) { v->storage=o->id;v->locks_before=s->locks; }
    if(c.api==SPX_DD_CREATE) {
        require(c.output!=NULL,"DirectDraw creation output");
        require(!c.input || (uintptr_t)c.input>65535,"DirectDraw special driver selectors");
        if(c.input)bytes(v,c.input,16);
    }
    if(c.api==SPX_DD_CREATE_SURFACE) { require(c.input && c.output,"surface creation arguments");descriptor(v,c.input); }
    if(c.api==SPX_DD_COOPERATIVE) { v->arguments[0]=c.arguments[0];v->argument_count=1; }
    if(c.api==SPX_DD_LOCK) {
        require(!c.handle && !(c.arguments[0]&~0x4831U),"surface lock event or flags");
        v->arguments[0]=c.arguments[0];v->arguments[1]=c.input!=NULL;v->argument_count=2;
        if(c.input) { memcpy(v->arguments+2,c.input,16);v->argument_count=6; }
    }
    if(c.api==SPX_DD_LOCK || c.api==SPX_DD_DESCRIBE) {
        const spx_wine_surface_desc *d=c.output;require(d && d->words[0]==108 && !d->words[9],"surface output ABI size");
        if(e->mode==SPX_WINE_CONTROLLED) { v->byte_mask=calloc(108,1);require(v->byte_mask!=NULL,"descriptor write footprint allocation"); }
    }
    if(c.api==SPX_DD_UNLOCK) {
        require(!c.buffer || (s->locks && c.buffer==s->locked_pixels),"surface unlock pointer correspondence");
        v->arguments[0]=c.buffer!=NULL;v->argument_count=1;
        if(s->locks) {
            uint64_t n=(uint64_t)s->width*s->pixel_bytes*s->height;require(n<=DRAW_BYTES,"locked pixel observation extent");
            v->data_bytes=(size_t)n;v->data=malloc((size_t)n);require(v->data!=NULL,"locked pixel observation allocation");
            for(uint32_t y=0;y<s->height;++y)memcpy(v->data+(size_t)y*s->width*s->pixel_bytes,
                (unsigned char *)s->locked_pixels+(int64_t)y*s->pitch,(size_t)s->width*s->pixel_bytes);
        }
    }
    if(c.api==SPX_DD_BLT) {
        const spx_wine_blt *b=c.input;
        require(b && !b->source && !b->source_rect && (b->flags&0x400) && !(b->flags&~0x9000400U) && b->effects_size==100,"DirectDraw Blt currently supports color fill with optional wait flags");
        v->arguments[0]=b->flags;v->arguments[1]=b->effects_size;v->arguments[2]=b->fill_color;
        v->arguments[3]=b->destination!=NULL;v->argument_count=4;
        if(b->destination) { memcpy(v->arguments+4,b->destination,16);v->argument_count=8; }
    }
    if(e->hooks.before)e->hooks.before(e->hooks.context,v);
    if(c.api==SPX_DD_COOPERATIVE)v->window=spx_wine_window_identity(e,c.window);
    spx_wine_rule r=spx_wine_select_rule(e,c.api,v->receiver,v->occurrence);
    v->result=e->mode==SPX_WINE_NATIVE ? native(e,&c,v) : controlled(e,&c,v,&r);
    if(c.api==SPX_DD_LOCK || c.api==SPX_DD_DESCRIBE) {
        spx_wine_surface_desc *d=c.output;descriptor(v,d);
        if(!failed(v->result) && !(r.flags&SPX_RULE_NO_WRITE)) {
            if(c.api==SPX_DD_LOCK) {
                require(!s->locks && d->pixels && (d->words[1]&0x100e)==0x100e,"returned surface lock layout");
                s->locked_pixels=d->pixels;s->width=d->words[3];s->height=d->words[2];s->pitch=signed_word(d->words[4]);
                if(c.input) {
                    const spx_wine_rect *r=c.input;
                    int64_t width=(int64_t)r->right-r->left,height=(int64_t)r->bottom-r->top;
                    require(width>0 && height>0 && width<=s->width && height<=s->height,"returned surface rectangle extent");
                    s->width=(uint32_t)width;s->height=(uint32_t)height;
                }
                s->pixel_bytes=pixel_bytes(d);s->locks=1;
                require(s->width && s->height && (uint64_t)s->width*s->height*s->pixel_bytes<=DRAW_BYTES,"returned surface lock extent");
                uint64_t stride=s->pitch<0 ? -(int64_t)s->pitch : s->pitch;
                require(stride>=s->width*s->pixel_bytes,"returned surface pitch extent");
            }
        }
    }
    if(c.api==SPX_DD_UNLOCK && !failed(v->result)) { s->locks=0;s->locked_pixels=NULL; }
    if(r.flags&SPX_RULE_CALLBACK) {
        require(e->hooks.callback!=NULL,"DirectDraw callback binding");v->callback=r.callback;e->hooks.callback(e->hooks.context,r.callback);
    }
    if(o)v->references_after=o->state.references;
    if(s) { v->locks_after=s->locks;v->storage_extent=o->size; }
    if(e->hooks.after)e->hooks.after(e->hooks.context,v);
    return v->result;
}
void spx_wine_draw_destroy(spx_wine_env *e) { for(unsigned i=0;i<e->object_count;++i)free(e->objects[i].surface); }
void spx_wine_draw_observe(spx_wine_env *e,spx_observer *out) {
    int any=0;for(unsigned i=0;i<e->object_count;++i)any|=e->objects[i].kind==SPX_WINE_DD_SURFACE;
    if(!any)return;
    spx_observe_array(out,"surfaces");
    for(unsigned i=0;i<e->object_count;++i) {
        spx_wine_object *o=&e->objects[i];if(o->kind!=SPX_WINE_DD_SURFACE)continue;draw_surface *s=surface(o);
        spx_observe_object(out,NULL);spx_observe_u64(out,"identity",o->id);spx_observe_u64(out,"references",o->state.references);
        if(o->input_identity)spx_observe_u64(out,"borrowed_input",o->input_identity);
        spx_observe_u64(out,"locks",s->locks);
        if(e->mode==SPX_WINE_CONTROLLED)spx_observe_bytes(out,"backing",o->bytes,o->size);
        spx_observe_end(out);
    }
    spx_observe_end(out);
}
