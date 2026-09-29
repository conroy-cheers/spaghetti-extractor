/* Controlled platform adapter and explicit PE32/portable-state transport.
 * This file implements no initialization, reset, binding or blit algorithm. */
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "runtime.h"
#include "spx-observation.h"
#ifndef DX_NATIVE_ORACLE
#include "behavioral-c.h"

spx_step_result spx_sub_0000cd5c(spx_runtime *, spx_machine_state *, uint32_t);
#endif
enum { DRAW=0x600000, DRAW_TABLE=0x601000, SHOW=0x602000,
  COOPERATIVE=0x602004, CAPS=0x602008, SURFACE=0x60200c,
  CLIPPER_CREATE=0x602010, ATTACH=0x602014, BLIT=0x602018,
  CLIPPER_WINDOW=0x60201c, PRIMARY=0x610000, BACKBUFFER=0x610100,
  CLIPPER=0x610200, PRIMARY_TABLE=0x611000, BACKBUFFER_TABLE=0x611100,
  CLIPPER_TABLE=0x611200, SPRITE=0x620000, STACK=0x700400,
  BANKS=0x433d18, BANK_BYTES=0x418, RETURN_ADDRESS=0x12345678 };
typedef struct { uint32_t address, value; } cell;
typedef struct {
  dx_graphics state;
  struct dx_sprite sprites[3];
  uint32_t seed, window_base, caps_bits, pixels[2];
  unsigned failure, positive, callback, caps_failure;
  unsigned live[4], window_live[3], window_hidden[3];
  cell memory[2048]; unsigned cells;
  uint32_t events[48][12]; unsigned event_count;
} fixture;
static fixture storage;
static unsigned selected_calls[4];
static const struct { uint32_t address; size_t offset; } globals[] = {
  {0x434974,offsetof(dx_graphics,window)},
  {0x4349a8,offsetof(dx_graphics,directdraw)},
  {0x4349ac,offsetof(dx_graphics,primary)},
  {0x4349b4,offsetof(dx_graphics,backbuffer)},
  {0x4349bc,offsetof(dx_graphics,clipper)},
  {0x43499c,offsetof(dx_graphics,clipper_mode)},
  {0x4179fc,offsetof(dx_graphics,capability_mode)},
  {0x417a04,offsetof(dx_graphics,initialized)},
  {0x417a08,offsetof(dx_graphics,video_memory)},
  {0x434960,offsetof(dx_graphics,current_surface)},
  {0x434968,offsetof(dx_graphics,bank_index)}
};
static void dx_require_at(int condition, const char *expression, const char *file,
                   unsigned line, const char *function) {
  if (!condition) {
    fprintf(stderr,"invalid graphics fixture state/argument/lifetime at %s:%u (%s): %s\n",
            file,line,function,expression);
    exit(3);
  }
}
void dx_require(int condition) {
  dx_require_at(condition,"condition",__FILE__,__LINE__,__func__);
}
/* Private diagnostics for this adapter and native-runtime.c, which includes it.
 * Keep the shared callable boundary unchanged and evaluate each condition once. */
#define dx_require(condition) \
  dx_require_at((condition), #condition, __FILE__, __LINE__, __func__)
void dx_enter(unsigned unit) { dx_require(unit<4); ++selected_calls[unit]; }
void dx_check_selected(unsigned unit, int success) {
  dx_require(unit<4 && selected_calls[unit]>0);
  if (unit==3 && success)
    dx_require(selected_calls[0]==1 && selected_calls[1]==2 && selected_calls[2]==2);
  fprintf(stderr,"DX_SELECTED %u %u %u %u\n",selected_calls[0],selected_calls[1],selected_calls[2],selected_calls[3]);
}
static fixture *owner(dx_graphics *state) {
  dx_require(state==&storage.state); return &storage;
}
static void put(fixture *f, uint32_t address, uint32_t value) {
  for (unsigned i=0;i<f->cells;++i)
    if (f->memory[i].address==address) { f->memory[i].value=value; return; }
  dx_require(f->cells<2048); f->memory[f->cells++]=(cell){address,value};
}
static uint32_t get(fixture *f, uint32_t address) {
  for (unsigned i=0;i<f->cells;++i)
    if (f->memory[i].address==address) return f->memory[i].value;
  fprintf(stderr,"uninitialized machine read %08x\n",address); exit(3);
}
static void record(fixture *f, uint32_t id, const uint32_t *args, unsigned count) {
  dx_require(f->event_count<48 && count<12);
  uint32_t *event=f->events[f->event_count++]; event[0]=id;
  for (unsigned i=0;i<count;++i) event[i+1]=args[i];
}
static unsigned window_index(fixture *f, uint32_t window) {
  dx_require(window>=f->window_base && (window-f->window_base)%16==0);
  unsigned index=(window-f->window_base)/16;
  dx_require(index<3 && f->window_live[index]); return index;
}
static void live(fixture *f, uint32_t handle, unsigned kind) {
  static const uint32_t handles[]={DRAW,PRIMARY,BACKBUFFER,CLIPPER};
  dx_require(kind<4 && f->live[kind] && handle==handles[kind]);
}
static int32_t status(fixture *f, unsigned point) {
  return f->failure==point ? (f->positive ? 1 : -1) : 0;
}
static void window_callback(fixture *f, unsigned point) {
  if (f->callback & point) {
    uint32_t old=f->state.window;
    unsigned index=window_index(f,old); dx_require(index<2);
    f->state.window=old+16;
    uint32_t args[]={point,old,f->state.window}; record(f,13,args,3);
  }
}
int32_t dx_create_draw(void *unused, dx_graphics *state) {
  (void)unused; fixture *f=owner(state); window_index(f,state->window);
  dx_require(!f->live[0]); int32_t result=status(f,1);
  if (result>=0) { f->live[0]=1; state->directdraw=DRAW; }
  uint32_t args[]={(uint32_t)result,state->directdraw}; record(f,1,args,2); return result;
}
int32_t dx_cooperative(void *unused, dx_graphics *state, uint32_t draw,
                       uint32_t window, uint32_t flags) {
  (void)unused; fixture *f=owner(state); live(f,draw,0); window_index(f,window);
  dx_require(flags==8); int32_t result=status(f,2);
  uint32_t args[]={draw,window,flags,(uint32_t)result}; record(f,2,args,4); return result;
}
uint32_t dx_caps(void *unused, dx_graphics *state, uint32_t draw) {
  (void)unused; fixture *f=owner(state); live(f,draw,0);
  dx_require(state->initialized==1 && state->capability_mode==0);
  uint32_t args[]={draw,f->caps_failure ? UINT32_MAX : 0,f->caps_bits};
  record(f,3,args,3); return f->caps_bits;
}
int32_t dx_create_surface(void *unused, dx_graphics *state, uint32_t draw,
                          uint32_t kind) {
  (void)unused; fixture *f=owner(state); live(f,draw,0); dx_require(kind<2);
  dx_require(!f->live[kind+1]); int32_t result=status(f,kind+3);
  uint32_t *slot=kind ? &state->backbuffer : &state->primary;
  if (result>=0) { f->live[kind+1]=1; *slot=kind ? BACKBUFFER : PRIMARY; }
  uint32_t args[]={draw,kind,(uint32_t)result,*slot}; record(f,4,args,4); return result;
}
int32_t dx_create_clipper(void *unused, dx_graphics *state, uint32_t draw) {
  (void)unused; fixture *f=owner(state); live(f,draw,0); dx_require(!f->live[3]);
  int32_t result=status(f,5);
  if (result>=0) { f->live[3]=1; state->clipper=CLIPPER; }
  uint32_t args[]={draw,(uint32_t)result,state->clipper}; record(f,5,args,3); return result;
}
int32_t dx_clipper_window(void *unused, dx_graphics *state, uint32_t clipper,
                          uint32_t window) {
  (void)unused; fixture *f=owner(state); live(f,clipper,3); window_index(f,window);
  int32_t result=status(f,6);
  uint32_t args[]={clipper,window,(uint32_t)result}; record(f,6,args,3); return result;
}
int32_t dx_attach(void *unused, dx_graphics *state, uint32_t primary, uint32_t clipper) {
  (void)unused; fixture *f=owner(state); live(f,primary,1); live(f,clipper,3);
  int32_t result=status(f,7);
  uint32_t args[]={primary,clipper,(uint32_t)result}; record(f,7,args,3); return result;
}
void dx_hide(void *unused, dx_graphics *state, uint32_t window) {
  (void)unused; fixture *f=owner(state); f->window_hidden[window_index(f,window)]=1;
  uint32_t args[]={window}; record(f,8,args,1); window_callback(f,1);
}
uint32_t dx_message(void *unused, dx_graphics *state, uint32_t window, uint32_t kind) {
  (void)unused; fixture *f=owner(state); window_index(f,window); dx_require(kind>=1 && kind<=7);
  uint32_t args[]={window,kind}; record(f,9,args,2); window_callback(f,2); return 17;
}
void dx_destroy(void *unused, dx_graphics *state, uint32_t window) {
  (void)unused; fixture *f=owner(state); f->window_live[window_index(f,window)]=0;
  uint32_t args[]={window}; record(f,10,args,1);
}
uint32_t dx_blit_fast(void *unused, dx_graphics *state, uint32_t destination,
    uint32_t x, uint32_t y, uint32_t source, uint32_t left, uint32_t top,
    uint32_t right, uint32_t bottom, uint32_t flags) {
  (void)unused; fixture *f=owner(state);
  unsigned target=destination==PRIMARY ? 0 : 1;
  live(f,destination,target+1); live(f,source,source==PRIMARY ? 1 : 2);
  dx_require(flags==0x11 && right>=left && bottom>=top);
  uint32_t result=f->seed%3==0 ? UINT32_MAX : f->seed%3==1 ? 0 : 1;
  if ((int32_t)result>=0) f->pixels[target]^=source+x+3*y+left+5*top+7*right+11*bottom;
  uint32_t args[]={destination,x,y,source,left,top,right,bottom,flags,result};
  record(f,11,args,10); return result;
}
static uint32_t sprite_address(fixture *f, const struct dx_sprite *sprite) {
  if (!sprite) return 0;
  for (unsigned i=0;i<3;++i) if (sprite==&f->sprites[i]) return SPRITE+64*i;
  dx_require(0); return 0;
}
static struct dx_sprite *sprite_pointer(fixture *f, uint32_t address) {
  if (!address) return NULL;
  dx_require(address>=SPRITE && (address-SPRITE)%64==0 && (address-SPRITE)/64<3);
  return &f->sprites[(address-SPRITE)/64];
}
static void store_state(fixture *f) {
  for (unsigned i=0;i<sizeof(globals)/sizeof(*globals);++i)
    put(f,globals[i].address,*(uint32_t *)((char *)&f->state+globals[i].offset));
  for (unsigned b=0;b<3;++b) {
    for (unsigned j=0;j<255;++j)
      put(f,BANKS+BANK_BYTES*b+4*j,sprite_address(f,f->state.banks[b].slots[j]));
    put(f,BANKS+BANK_BYTES*b+0x3fc,f->state.banks[b].count);
    for (unsigned j=0;j<6;++j) put(f,BANKS+BANK_BYTES*b+0x400+4*j,f->state.banks[b].retained[j]);
    put(f,SPRITE+64*b,f->sprites[b].surface);
    for (unsigned j=0;j<4;++j) put(f,SPRITE+64*b+0x14+4*j,f->sprites[b].rectangle[j]);
  }
}
static void load_state(fixture *f) {
  for (unsigned i=0;i<sizeof(globals)/sizeof(*globals);++i)
    *(uint32_t *)((char *)&f->state+globals[i].offset)=get(f,globals[i].address);
  for (unsigned b=0;b<3;++b) {
    for (unsigned j=0;j<255;++j)
      f->state.banks[b].slots[j]=sprite_pointer(f,get(f,BANKS+BANK_BYTES*b+4*j));
    f->state.banks[b].count=get(f,BANKS+BANK_BYTES*b+0x3fc);
    for (unsigned j=0;j<6;++j) f->state.banks[b].retained[j]=get(f,BANKS+BANK_BYTES*b+0x400+4*j);
  }
}
#ifndef DX_NATIVE_ORACLE
static uint32_t machine_read(void *opaque, uint32_t address, uint32_t width, uint32_t *fault) {
  (void)fault; dx_require(width==4); return get(opaque,address);
}
static void machine_write(void *opaque, uint32_t address, uint32_t width,
                           uint32_t value, uint32_t *fault) {
  (void)fault; dx_require(width==4);
  int allowed=(address>=STACK-0x100 && address<STACK+0x300) ||
      (address>=BANKS && address<BANKS+3*BANK_BYTES);
  for (unsigned i=0;i<sizeof(globals)/sizeof(*globals);++i) allowed|=address==globals[i].address;
  if (!allowed) fprintf(stderr,"unexpected machine write %08x\n",address);
  dx_require(allowed); put(opaque,address,value);
}
static spx_runtime runtime(fixture *f) {
  spx_runtime rt={0}; rt.context=f; rt.image_base=0x400000;
  rt.read=machine_read; rt.write=machine_write; return rt;
}
spx_call_status spx_invoke_call(spx_runtime *rt, const spx_call_event *event,
    const spx_machine_state *in, spx_machine_state *out) {
  fixture *f=rt->context; uint32_t a=get(f,in->esp), n=0, result=0;
  *out=*in; load_state(f); dx_graphics *s=&f->state;
  if (event->instruction_rva==0xcfe7 || event->instruction_rva==0xcff3) {
    uint32_t entry=event->instruction_rva==0xcfe7 ? 0xbc90 : 0xbd60;
    dx_require(event->kind==SPX_CALL_INTERNAL_DIRECT && event->target_rva==entry);
    out->esp-=4; put(f,out->esp,RETURN_ADDRESS);
    spx_step_result step=entry==0xbc90 ? spx_sub_0000bc90(rt,out,entry) : spx_sub_0000bd60(rt,out,entry);
    dx_require(step.kind==SPX_RETURN && out->esp==in->esp);
    load_state(f); return SPX_CALL_OK;
  }
  switch (event->instruction_rva) {
    case 0xcd65:
      dx_require(event->kind==SPX_CALL_EXTERNAL_IMPORT && !strcmp(event->dll,"ddraw.dll") && !strcmp(event->symbol,"DirectDrawCreate"));
      dx_require(a==0 && get(f,in->esp+4)==0x4349a8 && get(f,in->esp+8)==0);
      result=(uint32_t)dx_create_draw(NULL,s); n=3; break;
    case 0xcdba:
      dx_require(event->kind==SPX_CALL_INDIRECT && event->target_rva==COOPERATIVE);
      result=(uint32_t)dx_cooperative(NULL,s,a,get(f,in->esp+4),get(f,in->esp+8)); n=3; break;
    case 0xce2e: {
      dx_require(event->kind==SPX_CALL_INDIRECT && event->target_rva==CAPS);
      uint32_t buffer=get(f,in->esp+4); dx_require(get(f,buffer)==0x17c && get(f,in->esp+8)==0);
      put(f,buffer+4,dx_caps(NULL,s,a)); result=f->caps_failure ? UINT32_MAX : 0; n=3; break;
    }
    case 0xce6d: case 0xcee6: {
      dx_require(event->kind==SPX_CALL_INDIRECT && event->target_rva==SURFACE);
      unsigned kind=event->instruction_rva==0xcee6;
      uint32_t desc=get(f,in->esp+4);
      dx_require(get(f,desc)==0x6c && get(f,desc+4)==(kind ? 7U : 1U));
      dx_require(get(f,desc+0x68)==(kind ? 0x40U : 0x200U));
      dx_require(get(f,in->esp+8)==(kind ? 0x4349b4U : 0x4349acU) && get(f,in->esp+12)==0);
      if (kind) dx_require(get(f,desc+8)==480 && get(f,desc+12)==640);
      result=(uint32_t)dx_create_surface(NULL,s,a,kind); n=4; break;
    }
    case 0xcf45:
      dx_require(event->kind==SPX_CALL_INDIRECT && event->target_rva==CLIPPER_CREATE);
      dx_require(get(f,in->esp+4)==0 && get(f,in->esp+8)==0x4349bc && get(f,in->esp+12)==0);
      result=(uint32_t)dx_create_clipper(NULL,s,a); n=4; break;
    case 0xcf76:
      dx_require(event->kind==SPX_CALL_INDIRECT && event->target_rva==CLIPPER_WINDOW && get(f,in->esp+4)==0);
      result=(uint32_t)dx_clipper_window(NULL,s,a,get(f,in->esp+8)); n=3; break;
    case 0xcfa5:
      dx_require(event->kind==SPX_CALL_INDIRECT && event->target_rva==ATTACH);
      result=(uint32_t)dx_attach(NULL,s,a,get(f,in->esp+4)); n=2; break;
    case 0xcd77: case 0xcdc9: case 0xce7c: case 0xcef5: case 0xcf55: case 0xcf86: case 0xcfb5:
      dx_require(event->kind==SPX_CALL_INDIRECT && event->target_rva==SHOW && get(f,in->esp+4)==0);
      dx_hide(NULL,s,a); n=2; break;
    case 0xcd8c: case 0xcdde: case 0xce91: case 0xcf0a: case 0xcfc9: {
      static const uint32_t messages[]={0x417aac,0x417bf0,0x417bc0,0x417b8c,0x417b5c,0x417b24,0x417ae8};
      dx_require(event->kind==SPX_CALL_EXTERNAL_IMPORT && !strcmp(event->dll,"user32.dll") && !strcmp(event->symbol,"MessageBoxA"));
      dx_require(get(f,in->esp+8)==0x41639c && get(f,in->esp+12)==0);
      unsigned kind=0; uint32_t text=get(f,in->esp+4);
      for (unsigned i=0;i<7;++i) if (text==messages[i]) kind=i+1;
      result=dx_message(NULL,s,a,kind); n=4; break;
    }
    case 0xcd98: case 0xcdeb: case 0xce9e: case 0xcf17: case 0xcfd6:
      dx_require(event->kind==SPX_CALL_EXTERNAL_IMPORT && !strcmp(event->dll,"user32.dll") && !strcmp(event->symbol,"DestroyWindow"));
      dx_destroy(NULL,s,a); result=1; n=1; break;
    case 0xbdca: {
      dx_require(event->kind==SPX_CALL_INDIRECT && event->target_rva==BLIT);
      uint32_t rect=get(f,in->esp+16);
      result=dx_blit_fast(NULL,s,a,get(f,in->esp+4),get(f,in->esp+8),get(f,in->esp+12),
          get(f,rect),get(f,rect+4),get(f,rect+8),get(f,rect+12),get(f,in->esp+20)); n=6; break;
    }
    default:
      fprintf(stderr,"unsupported original graphics call %08x\n",event->instruction_rva); return SPX_CALL_UNIMPLEMENTED;
  }
  store_state(f); out->eax=result; out->esp+=4*n; return SPX_CALL_OK;
}
static spx_machine_state entry_state(fixture *f) {
  store_state(f); put(f,STACK,RETURN_ADDRESS);
  spx_machine_state state={0}; state.esp=STACK; state.esi=0x11111111;
  state.edi=0x22222222; state.ebx=0x33333333; return state;
}
void original_reset(dx_graphics *s) {
  fixture *f=owner(s); spx_runtime rt=runtime(f); spx_machine_state state=entry_state(f);
  spx_step_result step=spx_sub_0000bc90(&rt,&state,0xbc90);
  dx_require(step.kind==SPX_RETURN && state.esp==STACK+4 && state.esi==0x11111111 && state.edi==0x22222222);
  load_state(f);
}
void original_bind(dx_graphics *s, uint32_t surface) {
  fixture *f=owner(s); spx_runtime rt=runtime(f); spx_machine_state state=entry_state(f);
  put(f,STACK+4,surface); spx_step_result step=spx_sub_0000bd60(&rt,&state,0xbd60);
  dx_require(step.kind==SPX_RETURN && state.esp==STACK+4); load_state(f);
}
uint32_t original_blit(dx_graphics *s, uint32_t index, uint32_t x, uint32_t y) {
  fixture *f=owner(s); spx_runtime rt=runtime(f); spx_machine_state state=entry_state(f);
  put(f,STACK+4,index); put(f,STACK+8,x); put(f,STACK+12,y);
  spx_step_result step=spx_sub_0000bd90(&rt,&state,0xbd90);
  dx_require(step.kind==SPX_RETURN && state.esp==STACK+4 && state.esi==0x11111111);
  load_state(f); return state.eax;
}
uint32_t original_initialize(dx_graphics *s) {
  fixture *f=owner(s); spx_runtime rt=runtime(f); spx_machine_state state=entry_state(f);
  put(f,STACK,0x11111111); put(f,STACK+4,0x33333333); put(f,STACK+0x218,RETURN_ADDRESS);
  state.esi=SHOW;
  spx_step_result step=spx_sub_0000cd5c(&rt,&state,0xcd5c);
  dx_require(step.kind==SPX_RETURN && state.esp==STACK+0x21c && state.esi==0x11111111 && state.ebx==0x33333333);
  load_state(f); return state.eax;
}
#endif
dx_graphics *dx_setup(uint32_t seed, unsigned failure, int positive,
    unsigned clipper_mode, unsigned callback, unsigned caps_failure) {
  memset(&storage,0,sizeof(storage)); fixture *f=&storage; dx_graphics *s=&f->state;
  memset(selected_calls,0,sizeof(selected_calls));
  f->seed=seed; f->failure=failure; f->positive=(unsigned)positive;
  f->callback=callback; f->caps_failure=caps_failure; f->caps_bits=seed;
  f->window_base=0x1122+((seed%1000)*64); s->window=f->window_base;
  for (unsigned i=0;i<3;++i) f->window_live[i]=1;
  s->directdraw=91; s->primary=92; s->backbuffer=93; s->clipper=94;
  s->clipper_mode=clipper_mode; s->capability_mode=95; s->initialized=96;
  s->video_memory=97; s->current_surface=98; s->bank_index=seed%3;
  for (unsigned b=0;b<3;++b) {
    f->sprites[b].surface=BACKBUFFER;
    for (unsigned j=0;j<4;++j) f->sprites[b].rectangle[j]=b*10+j*7;
    for (unsigned j=0;j<255;++j) s->banks[b].slots[j]=&f->sprites[(seed+j+b)%3];
    s->banks[b].count=100+b;
    for (unsigned j=0;j<6;++j) s->banks[b].retained[j]=0xaabb0000+b*16+j;
  }
  for (uint32_t a=STACK-0x100;a<STACK+0x300;a+=4) put(f,a,0xcdcdcdcd);
  put(f,0x4349b0,0xabc01234); put(f,0x4349b8,0xdef05678);
  put(f,DRAW,DRAW_TABLE); put(f,DRAW_TABLE+0x50,COOPERATIVE);
  put(f,DRAW_TABLE+0x2c,CAPS); put(f,DRAW_TABLE+0x18,SURFACE); put(f,DRAW_TABLE+0x10,CLIPPER_CREATE);
  put(f,PRIMARY,PRIMARY_TABLE); put(f,PRIMARY_TABLE+0x70,ATTACH); put(f,PRIMARY_TABLE+0x1c,BLIT);
  put(f,BACKBUFFER,BACKBUFFER_TABLE); put(f,BACKBUFFER_TABLE+0x1c,BLIT);
  put(f,CLIPPER,CLIPPER_TABLE); put(f,CLIPPER_TABLE+0x20,CLIPPER_WINDOW);
  store_state(f); return s;
}
void dx_seed_live_resources(dx_graphics *s) {
  fixture *f=owner(s); f->live[0]=f->live[1]=f->live[2]=1;
  s->directdraw=DRAW; s->primary=PRIMARY; s->backbuffer=BACKBUFFER; s->current_surface=PRIMARY;
}
void dx_load_sprite(dx_graphics *s, unsigned bank, unsigned slot) {
  fixture *f=owner(s); dx_require(bank<3 && slot<255);
  live(f,s->backbuffer,2); s->bank_index=bank;
  s->banks[bank].slots[slot]=&f->sprites[bank]; s->banks[bank].count=slot+1;
}
void dx_observe(dx_graphics *s, const uint32_t *results, unsigned count) {
  fixture *f=owner(s);
  dx_require(get(f,0x4349b0)==0xabc01234 && get(f,0x4349b8)==0xdef05678);
  spx_observer out=spx_observe_begin(stdout);
  spx_observe_u32s(&out,"results",results,count);
  spx_observe_array(&out,"state");
  for (unsigned i=0;i<sizeof(globals)/sizeof(*globals);++i)
    spx_observe_u64(&out,NULL,*(uint32_t *)((char *)s+globals[i].offset));
  spx_observe_end(&out);spx_observe_array(&out,"banks");
  for (unsigned b=0;b<3;++b) {
    spx_observe_array(&out,NULL);
    for (unsigned j=0;j<255;++j) spx_observe_u64(&out,NULL,sprite_address(f,s->banks[b].slots[j]));
    spx_observe_u64(&out,NULL,s->banks[b].count);
    for (unsigned j=0;j<6;++j) spx_observe_u64(&out,NULL,s->banks[b].retained[j]);
    spx_observe_end(&out);
  }
  spx_observe_end(&out);spx_observe_array(&out,"resources");
  for (unsigned i=0;i<4;++i)spx_observe_u64(&out,NULL,f->live[i]);
  spx_observe_end(&out);spx_observe_array(&out,"windows");
  for (unsigned i=0;i<3;++i) {
    const uint32_t window[]={f->window_live[i],f->window_hidden[i]};
    spx_observe_u32s(&out,NULL,window,2);
  }
  spx_observe_end(&out);spx_observe_u32s(&out,"pixels",f->pixels,2);spx_observe_array(&out,"services");
  for (unsigned i=0;i<f->event_count;++i) {
    spx_observe_u32s(&out,NULL,f->events[i],12);
  }
  spx_observe_end(&out);dx_require(spx_observe_finish(&out));
}
