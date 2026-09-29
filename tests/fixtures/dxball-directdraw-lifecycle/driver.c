/* Fixture for two actual DX-Ball initialization failure paths. The original
 * oracle is retained machine-derived C, never an independently rewritten oracle.
 * Unknown machine reads/calls and unsupported source services fail the fixture.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "portable-component-implementation.h"
#include "behavioral-c.h"

enum { WINDOW = 0x1122, DRAW = 0x600000, TABLE = 0x601000,
       SHOW = 0x602000, COOPERATIVE = 0x602004, STACK = 0x700400 };
typedef struct {
  uint32_t address, value;
} cell;
typedef struct {
  int scenario, alive, draw_alive, hidden;
  uint32_t window;
  cell memory[128];
  size_t cells;
  uint32_t events[8][4];
  size_t event_count;
} fixture;
static void require(int condition) {
  if (!condition) { fputs("invalid lifecycle fixture state/argument/lifetime\n", stderr); exit(3); }
}
static void record(fixture *f, uint32_t id, uint32_t a, uint32_t b, uint32_t c) {
  require(f->event_count < 8);
  uint32_t *event = f->events[f->event_count++];
  event[0]=id; event[1]=a; event[2]=b; event[3]=c;
}
static void put(fixture *f, uint32_t address, uint32_t value) {
  for(size_t i=0;i<f->cells;i++) if(f->memory[i].address==address) { f->memory[i].value=value; return; }
  require(f->cells<128); f->memory[f->cells++]=(cell){address,value};
}
static uint32_t get(fixture *f, uint32_t address) {
  for(size_t i=0;i<f->cells;i++) if(f->memory[i].address==address) return f->memory[i].value;
  fprintf(stderr,"uninitialized machine read %08x\n",address); exit(3);
}
static uint32_t machine_read(void *opaque,uint32_t address,uint32_t width,uint32_t *fault) {
  (void)fault; require(width==4); return get(opaque,address);
}
static void machine_write(void *opaque,uint32_t address,uint32_t width,uint32_t value,uint32_t *fault) {
  (void)fault; require(width==4);
  require((address>=STACK-64 && address<STACK+0x220) || address==0x4349a8);
  put(opaque,address,value);
}
static int32_t create(void *opaque,spx_resource_v2 *out) {
  fixture *f=opaque; require(f->alive && !f->draw_alive);
  int32_t status=f->scenario<2 ? (f->scenario==0 ? -1 : 1) : 0;
  if(status>=0) { f->draw_alive=1; *out=(spx_resource_v2){2,1,DRAW}; }
  record(f,1,(uint32_t)status,f->draw_alive ? DRAW : 0,0); return status;
}
static uint32_t cooperative(void *opaque,spx_resource_v2 draw,spx_resource_v2 window,uint32_t flags) {
  fixture *f=opaque;
  require(f->alive && f->draw_alive && draw.identity==DRAW && draw.type_tag==2 && draw.generation==1);
  require(window.identity==f->window && window.type_tag==1 && window.generation==1 && flags==8);
  record(f,2,DRAW,f->window,flags); return f->scenario==2 ? UINT32_MAX : 1;
}
static void hide(void *opaque,spx_resource_v2 window) {
  fixture *f=opaque; require(f->alive && !f->hidden && window.identity==f->window && window.generation==1 && window.type_tag==1);
  f->hidden=1; record(f,3,f->window,0,0);
}
static uint32_t message(void *opaque,spx_resource_v2 window,uint32_t kind) {
  fixture *f=opaque; require(f->alive && f->hidden && window.identity==f->window && window.generation==1 && window.type_tag==1);
  record(f,4,f->window,kind,0); return 17;
}
static void destroy(void *opaque,spx_resource_v2 window) {
  fixture *f=opaque; require(f->alive && f->hidden && window.identity==f->window && window.generation==1 && window.type_tag==1);
  f->alive=0; record(f,5,f->window,0,0);
}
/* The generated slice exposes pre-call ESP: arguments start at offset zero.
 * Our implemented stdcall services pop exactly their argument bytes. */
spx_call_status spx_invoke_call(spx_runtime *rt,const spx_call_event *e,
    const spx_machine_state *in,spx_machine_state *out) {
  fixture *f=rt->context; uint32_t a=get(f,in->esp), n=0, result=0;
  spx_resource_v2 window={1,1,f->window}, draw={2,1,DRAW};
  *out=*in;
  switch(e->instruction_rva) {
    case 0xcd65: {
      require(e->kind==SPX_CALL_EXTERNAL_IMPORT && !strcmp(e->dll,"ddraw.dll") && !strcmp(e->symbol,"DirectDrawCreate"));
      require(a==0 && get(f,in->esp+4)==0x4349a8 && get(f,in->esp+8)==0);
      spx_resource_v2 created={0}; result=(uint32_t)create(f,&created);
      if((int32_t)result>=0) put(f,0x4349a8,(uint32_t)created.identity);
      n=3; break;
    }
    case 0xcdba:
      require(e->kind==SPX_CALL_INDIRECT && e->target_rva==COOPERATIVE);
      require(a==DRAW && get(f,in->esp+4)==f->window);
      result=cooperative(f,draw,window,get(f,in->esp+8)); n=3; break;
    case 0xcd77: case 0xcdc9:
      require(e->kind==SPX_CALL_INDIRECT && e->target_rva==SHOW);
      require(a==f->window && get(f,in->esp+4)==0);
      hide(f,window); n=2; break;
    case 0xcd8c: case 0xcdde:
      require(e->kind==SPX_CALL_EXTERNAL_IMPORT && !strcmp(e->dll,"user32.dll") && !strcmp(e->symbol,"MessageBoxA"));
      require(a==f->window && get(f,in->esp+8)==0x41639c && get(f,in->esp+12)==0);
      require(get(f,in->esp+4)==(e->instruction_rva==0xcd8c ? 0x417aacU : 0x417bf0U));
      result=message(f,window,e->instruction_rva==0xcd8c ? 1 : 2); n=4; break;
    case 0xcd98: case 0xcdeb:
      require(e->kind==SPX_CALL_EXTERNAL_IMPORT && !strcmp(e->dll,"user32.dll") && !strcmp(e->symbol,"DestroyWindow"));
      require(a==f->window); destroy(f,window); result=1; n=1; break;
    default:
      fprintf(stderr,"unsupported original call %08x\n",e->instruction_rva); return SPX_CALL_UNIMPLEMENTED;
  }
  out->eax=result; out->esp+=4*n; return SPX_CALL_OK;
}
static void observe(fixture *f,uint32_t result,const spx_directdraw_init_context_v5 *context) {
  printf("{\"result\":%u,\"window_alive\":%d,\"window_hidden\":%d,\"draw_alive\":%d,\"state\":[",result,f->alive,f->hidden,f->draw_alive);
  printf("%u,%u,%u,%u,%u,%u,%u,%u],\"services\":[",context->state.backbuffer_word,context->state.clipper_mode,context->state.clipper_word,context->state.capability_mode,context->state.directdraw_word,context->state.primary_word,context->state.directdraw_initialized,context->state.video_memory_capability);
  for(size_t i=0;i<f->event_count;i++) printf("%s[%u,%u,%u,%u]",i ? ",":"",f->events[i][0],f->events[i][1],f->events[i][2],f->events[i][3]);
  puts("]}");
}
int main(int argc,char **argv) {
  if(argc!=3 || (strcmp(argv[1],"original") && strcmp(argv[1],"source"))) return 2;
  char *end; long scenario=strtol(argv[2],&end,10);
  if(!*argv[2] || *end || scenario<0 || scenario>7) return 2;
  fixture f={0}; f.scenario=(int)scenario%4; f.alive=1; f.window=WINDOW+(uint32_t)scenario*16;
  spx_directdraw_init_services_v5 services={0}; services.context=&f;
  services.directdraw_create=create; services.set_cooperative_level=cooperative;
  services.hide_window=hide; services.message_box=message; services.destroy_window=destroy;
  spx_directdraw_init_context_v5 context={0}; context.services=&services;
  /* Sentinels make unintended writes observable; no original-side reset assumed. */
  context.state.backbuffer_word=91; context.state.clipper_mode=1; context.state.clipper_word=92;
  context.state.capability_mode=93; context.state.directdraw_word=94; context.state.primary_word=95;
  context.state.directdraw_initialized=96; context.state.video_memory_capability=97;
  uint32_t result;
  if(!strcmp(argv[1],"source")) {
    result=dxball_directdraw_initialize(&context,(spx_resource_v2){1,1,f.window});
  } else {
    put(&f,STACK,0x11111111); put(&f,STACK+4,0x22222222); put(&f,STACK+0x218,0x33333333);
    put(&f,0x434974,f.window);
    put(&f,0x4349b8,context.state.backbuffer_word);
    put(&f,0x4179fc,context.state.capability_mode);
    put(&f,0x43499c,context.state.clipper_mode);
    put(&f,0x4349bc,context.state.clipper_word);
    put(&f,0x417a04,context.state.directdraw_initialized);
    put(&f,0x4349a8,context.state.directdraw_word);
    put(&f,0x4349b4,context.state.primary_word);
    put(&f,0x417a08,context.state.video_memory_capability);

    put(&f,DRAW,TABLE); put(&f,TABLE+0x50,COOPERATIVE);
    spx_runtime rt={0}; rt.context=&f; rt.image_base=0x400000; rt.read=machine_read; rt.write=machine_write;
    spx_machine_state state={0}; state.esp=STACK; state.esi=SHOW;
    spx_step_result step=spx_sub_0000cd5c(&rt,&state,0xcd5c);
    require(step.kind==SPX_RETURN && state.esp==STACK+0x21c && state.esi==0x11111111 && state.ebx==0x22222222);
    result=state.eax;
    context.state.backbuffer_word=get(&f,0x4349b8);
    context.state.capability_mode=get(&f,0x4179fc);
    context.state.clipper_mode=get(&f,0x43499c);
    context.state.clipper_word=get(&f,0x4349bc);
    context.state.directdraw_initialized=get(&f,0x417a04);
    context.state.directdraw_word=get(&f,0x4349a8);
    context.state.primary_word=get(&f,0x4349b4);
    context.state.video_memory_capability=get(&f,0x417a08);

  }
  observe(&f,result,&context); return 0;
}
