/* Independent surface caller; no target addresses or application layouts. */
#define CINTERFACE 1
#define COBJMACROS 1
#ifdef _WIN32
#include <windows.h>
#include <ddraw.h>
#endif
#include "spx-wine-test.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define CHECK(x) do { if(!(x)) { fprintf(stderr,"draw consumer line %d\n",__LINE__);exit(42); } } while(0)
static spx_wine_env *environment;
static spx_wine_object *callback_surface;
static unsigned callbacks;
static uint32_t call(enum spx_wine_api api,spx_wine_object *o,void *out,const void *in,uint32_t value) {
#if defined(_WIN32) && !defined(USE_BINDING)
    IDirectDraw *device=(void *)o;IDirectDrawSurface *surf=(void *)o;
    if(api==SPX_DD_CREATE)return (uint32_t)DirectDrawCreate(NULL,out,NULL);
    if(api==SPX_DD_COOPERATIVE)return (uint32_t)IDirectDraw_SetCooperativeLevel(device,NULL,value);
    if(api==SPX_DD_CREATE_SURFACE) {
        const spx_wine_surface_desc *d=in;DDSURFACEDESC desc;memcpy(&desc,d->words,108);desc.lpSurface=d->pixels;
        return (uint32_t)IDirectDraw_CreateSurface(device,&desc,out,NULL);
    }
    if(api==SPX_DD_DESCRIBE || api==SPX_DD_LOCK) {
        spx_wine_surface_desc *d=out;DDSURFACEDESC desc;RECT rect;memcpy(&desc,d->words,108);desc.lpSurface=d->pixels;
        if(in)memcpy(&rect,in,16);
        uint32_t r=api==SPX_DD_DESCRIBE ? (uint32_t)IDirectDrawSurface_GetSurfaceDesc(surf,&desc) :
            (uint32_t)IDirectDrawSurface_Lock(surf,in ? &rect : NULL,&desc,value,NULL);
        memcpy(d->words,&desc,108);d->words[9]=0;d->pixels=desc.lpSurface;return r;
    }
    if(api==SPX_DD_UNLOCK)return (uint32_t)IDirectDrawSurface_Unlock(surf,(void *)in);
    if(api==SPX_DD_BLT) {
        const spx_wine_blt *b=in;DDBLTFX fx={0};RECT rect;
        if(b->destination)memcpy(&rect,b->destination,16);
        fx.dwSize=b->effects_size;fx.dwFillColor=b->fill_color;
        return (uint32_t)IDirectDrawSurface_Blt(surf,b->destination ? &rect : NULL,NULL,NULL,b->flags,&fx);
    }
    if(api==SPX_COM_QUERY)return (uint32_t)IDirectDrawSurface_QueryInterface(surf,in,out);
    if(api==SPX_COM_ADDREF)return IDirectDrawSurface_AddRef(surf);
    if(api==SPX_COM_RELEASE)return ((IUnknown *)o)->lpVtbl->Release((IUnknown *)o);
    CHECK(0);return 1;
#else
    spx_wine_call c={0};c.api=api;c.receiver=o;c.output=out;c.input=in;c.arguments[0]=value;c.argument_count=1;
    if(api==SPX_DD_UNLOCK) { c.buffer=(void *)in;c.input=NULL; }
    return spx_wine_candidate_call(environment,c);
#endif
}
static spx_wine_surface_desc blank(void) { spx_wine_surface_desc d={0};d.words[0]=108;return d; }
static void callback(void *unused,uint32_t id) {
    (void)unused;CHECK(id==19);++callbacks;spx_wine_surface_desc d=blank();
    CHECK(call(SPX_DD_DESCRIBE,callback_surface,&d,NULL,0)==0 && d.words[3]==9);
}
static int64_t signed_word(uint32_t value) { return value<0x80000000U ? (int64_t)value : (int64_t)value-4294967296LL; }
#ifdef _WIN32
static int borrowed_case(uint32_t identity) {
    /* The application owns these interfaces; only its borrowed surface crosses
     * the observed boundary. No factory or COM ownership event is fabricated. */
    IDirectDraw *device=NULL;IDirectDrawSurface *native=NULL;
    CHECK(DirectDrawCreate(NULL,&device,NULL)==0);CHECK(IDirectDraw_SetCooperativeLevel(device,NULL,8)==0);
    DDSURFACEDESC d={0};d.dwSize=108;d.dwFlags=0x1007;d.dwWidth=4;d.dwHeight=3;d.ddsCaps.dwCaps=0x840;
    d.ddpfPixelFormat.dwSize=32;d.ddpfPixelFormat.dwFlags=0x40;d.ddpfPixelFormat.dwRGBBitCount=32;
    d.ddpfPixelFormat.dwRBitMask=0xff0000;d.ddpfPixelFormat.dwGBitMask=0xff00;d.ddpfPixelFormat.dwBBitMask=0xff;
    CHECK(IDirectDraw_CreateSurface(device,&d,&native,NULL)==0);
    environment=spx_wine_create(SPX_WINE_NATIVE);
    spx_wine_object *surf=spx_wine_bind_surface(environment,native,identity);
    CHECK(spx_wine_bind_surface(environment,native,identity)==surf);
    spx_wine_surface_desc view=blank();CHECK(call(SPX_DD_LOCK,surf,&view,NULL,0)==0);
    for(unsigned y=0;y<3;++y)memset((unsigned char *)view.pixels+(int64_t)y*signed_word(view.words[4]),0x56,16);
    CHECK(call(SPX_DD_UNLOCK,surf,NULL,NULL,0)==0);
    spx_observer out=spx_observe_begin(stdout);spx_wine_observe(environment,&out,"platform");
    CHECK(spx_observe_finish(&out));puts("");spx_wine_destroy(environment);
    IDirectDrawSurface_Release(native);IDirectDraw_Release(device);return 0;
}
#endif
int main(int argc,char **argv) {
    const char *mode=argc>1 ? argv[1] : "controlled";
#ifdef _WIN32
    if(!strcmp(mode,"borrowed") || !strcmp(mode,"borrowed-wrong-input"))return borrowed_case(!strcmp(mode,"borrowed") ? 7 : 8);
#endif
    int native=!strcmp(mode,"native"),negative=!strcmp(mode,"negative"),failures=!strcmp(mode,"failures");
    int defect=!strcmp(mode,"defect"),expired=!strcmp(mode,"expired"),unsupported=!strcmp(mode,"unsupported");
#ifdef _WIN32
    if(argc==99) { IDirectDraw *unused=NULL;DirectDrawCreate(NULL,&unused,NULL); }
#else
    CHECK(!native);
#endif
    environment=spx_wine_create(native ? SPX_WINE_NATIVE : SPX_WINE_CONTROLLED);
#ifdef _WIN32
    CHECK(spx_wine_install_draw(environment,NULL));
#endif
    spx_wine_set_hooks(environment,(spx_wine_hooks){.callback=callback});
    if(failures) {
        uint32_t prefix[]={108,0x100f,5,9,0xffffffe0};
        spx_wine_add_rule(environment,(spx_wine_rule){.api=SPX_DD_DESCRIBE,.occurrence=1,
            .flags=SPX_RULE_RETURN|SPX_RULE_BYTES,.result=0x80004005,.bytes=(const unsigned char *)prefix,.byte_count=sizeof(prefix)});
        spx_wine_add_rule(environment,(spx_wine_rule){.api=SPX_DD_LOCK,.occurrence=1,
            .flags=SPX_RULE_RETURN|SPX_RULE_NO_WRITE|SPX_RULE_CALLBACK,.result=0x8876021c,.callback=19});
        spx_wine_add_rule(environment,(spx_wine_rule){.api=SPX_DD_CREATE_SURFACE,.occurrence=2,
            .flags=SPX_RULE_RETURN|SPX_RULE_NO_WRITE,.result=0x80004005});
    }
    spx_wine_object *device=NULL,*surf=NULL;
    CHECK(call(SPX_DD_CREATE,NULL,&device,NULL,0)==0 && device);
    CHECK(call(SPX_DD_COOPERATIVE,device,NULL,NULL,8)==0);
    spx_wine_surface_desc spec=blank();spec.words[1]=0x1007;spec.words[2]=5;spec.words[3]=9;
    spec.words[18]=32;spec.words[19]=0x40;spec.words[21]=32;
    spec.words[22]=0xff0000;spec.words[23]=0xff00;spec.words[24]=0xff;spec.words[26]=0x840;
    if(negative) {
        unsigned char backing[60];memset(backing,0xa7,sizeof(backing));
        spec.words[1]|=8;spec.words[3]=7;spec.words[4]=0xfffffff4;spec.words[19]=0x60;spec.words[21]=8;
        spec.words[22]=spec.words[23]=spec.words[24]=0;
        surf=spx_wine_seed_surface(environment,2,&spec,backing,sizeof(backing));
    } else CHECK(call(SPX_DD_CREATE_SURFACE,device,&surf,&spec,0)==0 && surf);
    callback_surface=surf;
    spx_wine_surface_desc view=spec;view.words[5]=0x1234;
    CHECK(call(SPX_DD_DESCRIBE,surf,&view,NULL,0)==(failures ? 0x80004005U : 0));
    if(failures)CHECK(view.words[4]==0xffffffe0 && view.words[5]==0x1234 && !view.pixels);
    view=blank();
    if(unsupported) { call(SPX_DD_LOCK,surf,&view,NULL,2);return 43; }
    if(failures) {
        CHECK(call(SPX_DD_LOCK,surf,&view,NULL,0)==0x8876021c && callbacks==1);
        CHECK(view.words[0]==108 && !view.words[1] && !view.pixels);
    }
    CHECK(call(SPX_DD_LOCK,surf,&view,NULL,0)==0);
    unsigned bpp=view.words[21]/8;
    for(unsigned y=0;y<view.words[2];++y) {
        unsigned char *row=(unsigned char *)view.pixels+(int64_t)y*signed_word(view.words[4]);
        memset(row,0x31,view.words[3]*bpp);
    }
    CHECK(call(SPX_DD_UNLOCK,surf,NULL,view.pixels,0)==0);
    spx_wine_rect rect={1,1,5,4};uint32_t color=defect ? 0x87654321U : 0x12345678U;
    spx_wine_blt fill={.destination=&rect,.flags=0x400,.effects_size=100,.fill_color=color};
    CHECK(call(SPX_DD_BLT,surf,NULL,&fill,0)==0);
    view=blank();CHECK(call(SPX_DD_LOCK,surf,&view,NULL,0)==0);
    uint32_t mask=view.words[19]&0x20 ? 0xff : view.words[22]|view.words[23]|view.words[24];
    if(view.words[19]&1)mask|=view.words[25];
    for(unsigned y=0;y<view.words[2];++y)for(unsigned x=0;x<view.words[3];++x)for(unsigned c=0;c<bpp;++c) {
        unsigned char *row=(unsigned char *)view.pixels+(int64_t)y*signed_word(view.words[4]);
        unsigned char expected=y>=1 && y<4 && x>=1 && x<5 ? (unsigned char)((color&mask)>>(8*c)) : 0x31;
        if(row[x*bpp+c]!=expected) {
            fprintf(stderr,"%s pixel %u,%u byte %u: %u expected %u; format %x mask %x\n",mode,x,y,c,row[x*bpp+c],expected,view.words[19],view.words[25]);
            CHECK(row[x*bpp+c]==expected);
        }
    }
    CHECK(call(SPX_DD_UNLOCK,surf,NULL,NULL,0)==0);
    /* Sub-rectangle lock observation must follow the locked extent even when
     * Wine returns a descriptor for the full surface. */
    rect=(spx_wine_rect){2,2,4,4};view=blank();CHECK(call(SPX_DD_LOCK,surf,&view,&rect,0)==0);
    for(unsigned y=0;y<2;++y)memset((unsigned char *)view.pixels+(int64_t)y*signed_word(view.words[4]),0x52,2*bpp);
    CHECK(call(SPX_DD_UNLOCK,surf,NULL,view.pixels,0)==0);
    static const uint32_t iid[]={0x6c14db81,0x11cea733,0x200021a5,0x60e50baf};
    spx_wine_object *alias=NULL;CHECK(call(SPX_COM_QUERY,surf,&alias,iid,0)==0 && alias==surf);
    CHECK(call(SPX_COM_ADDREF,alias,NULL,NULL,0)>1);
    call(SPX_COM_RELEASE,alias,NULL,NULL,0);call(SPX_COM_RELEASE,alias,NULL,NULL,0);
    if(failures) {
        spx_wine_object *unchanged=surf;CHECK(call(SPX_DD_CREATE_SURFACE,device,&unchanged,&spec,0)==0x80004005 && unchanged==surf);
    }
    call(SPX_COM_RELEASE,surf,NULL,NULL,0);call(SPX_COM_RELEASE,device,NULL,NULL,0);
    if(expired) { view=blank();call(SPX_DD_DESCRIBE,surf,&view,NULL,0);return 43; }
    spx_observer out=spx_observe_begin(stdout);spx_wine_observe(environment,&out,"platform");
    CHECK(spx_observe_finish(&out));puts("");spx_wine_destroy(environment);return 0;
}
