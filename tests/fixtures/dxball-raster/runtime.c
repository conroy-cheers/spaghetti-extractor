#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "raster-runtime.h"
#include "spx-wine-test.h"
#define REQUIRE(x) do { if(!(x)) { fprintf(stderr,"raster boundary line %d: %s\n",__LINE__,#x);abort(); } } while(0)
#ifndef DX_STANDALONE
#include <windows.h>
#include "native-image.h"
#endif
static int source_side;
static unsigned mode,selected[2];
static spx_wine_env *environment;
static spx_wine_object *objects[2];
static font_surface surfaces[2]={{1},{2}};
static spx_wine_surface_desc descriptor;
void raster_enter(unsigned operation) { REQUIRE(operation<2);++selected[operation];memset(&descriptor,0,sizeof(descriptor));descriptor.words[0]=108;descriptor.words[1]=14; }
static spx_wine_object *object(font_surface *s) { REQUIRE(s && s->identity>=1 && s->identity<=2);return objects[s->identity-1]; }
static void view_from_descriptor(pcx_view *view) {
    view->width=descriptor.words[3];view->height=descriptor.words[2];view->image.pitch=descriptor.words[4];view->image.pixels=descriptor.pixels;
}
uint32_t raster_describe(void *unused,font_surface *s,pcx_view *view) {
    (void)unused;spx_wine_call c={0};c.api=SPX_DD_DESCRIBE;c.receiver=object(s);c.output=&descriptor;
    uint32_t result=spx_wine_candidate_call(environment,c);view_from_descriptor(view);return result;
}
uint32_t raster_lock(void *unused,font_surface *s,pcx_view *view) {
    (void)unused;spx_wine_call c={0};c.api=SPX_DD_LOCK;c.receiver=object(s);c.output=&descriptor;
    uint32_t result=spx_wine_candidate_call(environment,c);view_from_descriptor(view);return result;
}
uint32_t raster_unlock(void *unused,font_surface *s) {
    (void)unused;spx_wine_call c={0};c.api=SPX_DD_UNLOCK;c.receiver=object(s);return spx_wine_candidate_call(environment,c);
}
uint32_t raster_fill(void *unused,font_surface *s,font_rect *rect,uint32_t size,uint32_t flags,uint32_t color) {
    (void)unused;spx_wine_rect r={(int32_t)font_signed(rect->left),(int32_t)font_signed(rect->top),
        (int32_t)font_signed(rect->right),(int32_t)font_signed(rect->bottom)};
    spx_wine_blt b={.destination=&r,.flags=flags,.effects_size=size,.fill_color=color};
    spx_wine_call c={0};c.api=SPX_DD_BLT;c.receiver=object(s);c.input=&b;return spx_wine_candidate_call(environment,c);
}
static void invoke(unsigned operation,unsigned index,uint32_t x1,uint32_t y1,uint32_t x2,uint32_t y2,uint32_t color) {
#ifndef DX_STANDALONE
    if(!source_side) {
        ((void (*)(void *,uint32_t,uint32_t,uint32_t,uint32_t,uint32_t))(operation ? 0x40d990 : 0x40d850))(objects[index],x1,y1,x2,y2,color);return;
    }
#endif
    if(operation)fixture_raster_fill(&surfaces[index],x1,y1,x2,y2,color);
    else fixture_raster_line(&surfaces[index],x1,y1,x2,y2,color);
}
static void callback(void *unused,uint32_t token) {
    (void)unused;REQUIRE(token==11);font_rect rect={0,0,3,3};raster_fill(NULL,&surfaces[1],&rect,100,0x400,0x91);
}
#ifndef DX_STANDALONE
static void native_fallback(void) { REQUIRE(0); }
#endif
int main(int argc,char **argv) {
    REQUIRE(argc==3);source_side=!strcmp(argv[1],"source");mode=(unsigned)strtoul(argv[2],NULL,10);REQUIRE(mode<18);
    environment=spx_wine_create(SPX_WINE_CONTROLLED);spx_wine_set_hooks(environment,(spx_wine_hooks){.callback=callback});
    spx_wine_surface_desc spec={0};spec.words[0]=108;spec.words[1]=0x100f;spec.words[2]=12;spec.words[3]=16;
    spec.words[4]=mode==6 ? 0u-20 : 20;spec.words[18]=32;spec.words[19]=0x60;spec.words[21]=8;spec.words[26]=0x840;
    unsigned char initial[240];for(unsigned i=0;i<sizeof(initial);++i)initial[i]=(unsigned char)(i*13+7);
    objects[0]=spx_wine_seed_surface(environment,1,&spec,initial,sizeof(initial));
    spec.words[4]=20;objects[1]=spx_wine_seed_surface(environment,2,&spec,initial,sizeof(initial));
    if(mode==8 || mode==9) {
        uint32_t prefix[]={108,14,12,16,48};
        spx_wine_add_rule(environment,(spx_wine_rule){.api=SPX_DD_DESCRIBE,.occurrence=1,
            .flags=SPX_RULE_BYTES|SPX_RULE_RETURN,.bytes=(const unsigned char *)prefix,.byte_count=sizeof(prefix),.result=mode==9 ? 0x80004005 : 0});
    }
    if(mode==10 || mode==11)for(unsigned i=1;i<=2;++i)
        spx_wine_add_rule(environment,(spx_wine_rule){.api=SPX_DD_LOCK,.occurrence=i,
            .flags=SPX_RULE_RETURN|SPX_RULE_NO_WRITE,.result=mode==10 ? 0x8876021c : 1});
    if(mode==12)spx_wine_add_rule(environment,(spx_wine_rule){.api=SPX_DD_UNLOCK,.occurrence=1,.flags=SPX_RULE_RETURN,.result=0x80004005});
    if(mode==13)spx_wine_add_rule(environment,(spx_wine_rule){.api=SPX_DD_DESCRIBE,.occurrence=1,.flags=SPX_RULE_CALLBACK,.callback=11});
    if(mode==16)spx_wine_add_rule(environment,(spx_wine_rule){.api=SPX_DD_BLT,.occurrence=1,.flags=SPX_RULE_RETURN,.result=0x88760096});
#ifndef DX_STANDALONE
    if(source_side) { REQUIRE(install_raster_line(native_fallback));REQUIRE(install_raster_fill(native_fallback)); }
#endif
    if(mode==0) {
        static const uint32_t ends[][2]={{13,7},{13,3},{1,7},{1,3},{9,10},{5,10},{9,0},{5,0}};
        for(unsigned i=0;i<8;++i)invoke(0,i%2,7,5,ends[i][0],ends[i][1],0x90+i);
    } else if(mode==1)invoke(0,0,1,4,14,4,0x12345678);
    else if(mode==2)invoke(0,0,4,10,4,1,0x37);
    else if(mode==3)invoke(0,0,8,5,8,5,0x100);
    else if(mode==4) { invoke(0,0,0,0,5,2,0x55);invoke(0,1,0,0,2,5,0x66); }
    else if(mode==5) { invoke(0,0,11,9,2,0,0xff);invoke(0,1,2,0,11,9,0); }
    else if(mode==7)invoke(0,0,UINT32_MAX,1,5,1,0x87);
    else if(mode==14) { invoke(0,0,5,3,0x80000005,3,0xaa);invoke(0,1,5,3,0x80000005,0x80000003,0xaa); }
    else if(mode==15)invoke(1,0,1,2,14,10,0xabcdef12);
    else if(mode==16)invoke(1,0,0xfffffffd,0x80000000,UINT32_MAX,4,0xfacebeef);
    else if(mode==17) { invoke(0,0,0,0,14,9,0x48);invoke(1,0,2,2,9,8,0x77);invoke(0,1,1,10,13,0,0x91); }
    else invoke(0,0,1,2,13,7,0x45);
    if(source_side)REQUIRE(selected[0]+selected[1]>0);
    spx_observer out=spx_observe_begin(stdout);spx_wine_observe(environment,&out,"platform");
    REQUIRE(spx_observe_finish(&out));puts("");spx_wine_destroy(environment);return 0;
}
#ifndef DX_STANDALONE
struct native_startupinfo { int newmode; };
extern int __cdecl __getmainargs(int *,char ***,char ***,int,struct native_startupinfo *);
static void run_case(void) {
    int argc;char **argv,**environment;struct native_startupinfo startup={0};REQUIRE(!__getmainargs(&argc,&argv,&environment,0,&startup));
    int result=main(argc,argv);fflush(NULL);ExitProcess((UINT)result);
}
__declspec(dllexport) void dx_raster_anchor(void) {}
BOOL WINAPI DllMain(HINSTANCE instance,DWORD reason,void *reserved) {
    (void)instance;(void)reserved;return reason!=DLL_PROCESS_ATTACH || ((uintptr_t)GetModuleHandleA(NULL)==0x400000 && install_startup(run_case));
}
#endif
