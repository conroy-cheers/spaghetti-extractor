"""Conditional terminal cleanup recipe; ordinary application C is supplied separately."""

TEMPLATE = r'''#include "behavioral-c.h"
#include "portable-component-implementation.h"
#define RESOURCE @RESOURCE@U
#define CAPTION @CAPTION@U
#define WINDOW @WINDOW@U
#define EDIT @EDIT@U
#define SUPPRESS @SUPPRESS@U
static uint32_t initial_scratch,initial_extent,initial_output;
uint8_t __CPROVER_uninterpreted_readonly_byte(uint32_t);
static uint8_t current_byte(uint32_t address){
 if(address>=initial_scratch+initial_output && (uint64_t)address<(uint64_t)initial_scratch+initial_extent)return 0U;
 return __CPROVER_uninterpreted_readonly_byte(address);
}
@MEMORY_RUNTIME@
@VIEW_RUNTIME@
static struct {uint32_t input,output,removed;spx_view_v5 scratch;} spx_cut;
#include "authored.c"
@REFERENCE_RUNTIME@
struct call_record {uint32_t kind,a,b,c,d;uint8_t byte;uint32_t result;};
static struct call_record calls[5];static uint32_t probe;
struct environment {struct spx_mutable_world *world;uint32_t side,count,released,text,text_extent,scratch,scratch_extent;spx_view_v5 resource;const spx_view_v5 *text_view,*scratch_view,*caption_view;};
struct machine {struct environment *env;uint32_t stack;uint32_t word_0; uint32_t word_1; uint32_t word_2; uint32_t word_3; uint32_t word_4; uint32_t word_5; uint32_t word_6; uint32_t word_7; uint32_t word_8; uint32_t word_9; uint32_t word_10; uint32_t word_11; uint32_t word_12; uint32_t word_13; uint32_t word_14; uint32_t word_15; uint32_t word_16; uint32_t word_17; uint32_t word_18;};
static uint32_t transition(struct environment *e,uint32_t kind,uint32_t a,uint32_t b,uint32_t c,uint32_t d){
 __CPROVER_assert(e->count<5U,"tail-call-capacity");__CPROVER_assume(e->count<5U);
 if(!e->side){uint32_t result;calls[e->count]=(struct call_record){kind,a,b,c,d,spx_mutable_byte(e->world,probe),result};}
 else{
  struct call_record expected=calls[e->count];
  __CPROVER_assert(kind==expected.kind && a==expected.a && b==expected.b && c==expected.c && d==expected.d,"tail-call-order-and-arguments");
  __CPROVER_assert(spx_mutable_byte(e->world,probe)==expected.byte,"tail-call-current-memory");
 }
 if(kind==1U){
  __CPROVER_assert(!e->released && e->scratch && e->scratch_extent,"tail-copy-live-source");
  spx_mutable_event(e->world,e->text,e->text_extent,0U,1U,e->count);
 }
 if(kind==2U){__CPROVER_assert(!e->released,"tail-release-once");e->released=1U;}
 if(kind==3U)spx_mutable_event(e->world,RESOURCE,@RESOURCE_EXTENT@U,0U,1U,e->count);
 return calls[e->count++].result;
}
static uint32_t machine_read(void *opaque,uint32_t address,uint32_t width,uint32_t *fault){
 struct machine *m=opaque;struct environment *e=m->env;*fault=0U;
 if(address==m->stack-60 && width==4U)return m->word_0;
 if(address==m->stack-56 && width==4U)return m->word_1;
 if(address==m->stack-52 && width==4U)return m->word_2;
 if(address==m->stack-48 && width==4U)return m->word_3;
 if(address==m->stack-44 && width==4U)return m->word_4;
 if(address==m->stack-40 && width==4U)return m->word_5;
 if(address==m->stack-36 && width==4U)return m->word_6;
 if(address==m->stack-32 && width==4U)return m->word_7;
 if(address==m->stack-28 && width==4U)return m->word_8;
 if(address==m->stack-24 && width==4U)return m->word_9;
 if(address==m->stack-20 && width==4U)return m->word_10;
 if(address==m->stack-16 && width==4U)return m->word_11;
 if(address==m->stack-12 && width==4U)return m->word_12;
 if(address==m->stack-8 && width==4U)return m->word_13;
 if(address==m->stack-4 && width==4U)return m->word_14;
 if(address==m->stack+0 && width==4U)return m->word_15;
 if(address==m->stack+4 && width==4U)return m->word_16;
 if(address==m->stack+8 && width==4U)return m->word_17;
 if(address==m->stack+12 && width==4U)return m->word_18;
 if(address==SUPPRESS || address==WINDOW || address==EDIT){
  __CPROVER_assert(width==4U,"tail-global-word-width");
  uint32_t result=0;for(uint32_t i=0;i<4U;++i)result|=(uint32_t)spx_mutable_byte(e->world,address+i)<<(8U*i);return result;
 }
 if(width!=1U || address<e->text || (uint64_t)address>=(uint64_t)e->text+e->text_extent){*fault=1U;return 0U;}
 return spx_mutable_byte(e->world,address);
}
static void machine_write(void *opaque,uint32_t address,uint32_t width,uint32_t value,uint32_t *fault){
 struct machine *m=opaque;struct environment *e=m->env;*fault=0U;
 if(address==m->stack-60 && width==4U){m->word_0=value;return;}
 if(address==m->stack-56 && width==4U){m->word_1=value;return;}
 if(address==m->stack-52 && width==4U){m->word_2=value;return;}
 if(address==m->stack-48 && width==4U){m->word_3=value;return;}
 if(address==m->stack-44 && width==4U){m->word_4=value;return;}
 if(address==m->stack-40 && width==4U){m->word_5=value;return;}
 if(address==m->stack-36 && width==4U){m->word_6=value;return;}
 if(address==m->stack-32 && width==4U){m->word_7=value;return;}
 if(address==m->stack-28 && width==4U){m->word_8=value;return;}
 if(address==m->stack-24 && width==4U){m->word_9=value;return;}
 if(address==m->stack-20 && width==4U){m->word_10=value;return;}
 if(address==m->stack-16 && width==4U){m->word_11=value;return;}
 if(address==m->stack-12 && width==4U){m->word_12=value;return;}
 if(address==m->stack-8 && width==4U){m->word_13=value;return;}
 if(address==m->stack-4 && width==4U){m->word_14=value;return;}
 if(address==m->stack+0 && width==4U){m->word_15=value;return;}
 if(address==m->stack+4 && width==4U){m->word_16=value;return;}
 __CPROVER_assert(!e->released,"tail-no-use-after-release");
 if(width!=1U || address<e->scratch || (uint64_t)address>=(uint64_t)e->scratch+e->scratch_extent){*fault=1U;return;}
 spx_mutable_event(e->world,address,1U,value,0U,0U);
}
static uint32_t same_reference(spx_ref_v5 a,spx_ref_v5 b){return a.domain==b.domain && a.object==b.object && a.generation==b.generation && a.offset==b.offset && a.extent==b.extent && a.permissions==b.permissions;}
static uint32_t same_view(const spx_view_v5 *a,const spx_view_v5 *b){return same_reference(a->base,b->base) && a->extent==b->extent && a->element_width==b->element_width && a->context==b->context && a->access_context==b->access_context && a->read_u8==b->read_u8 && a->write_u8==b->write_u8 && a->read==b->read && a->write==b->write;}
static struct environment *source_environment;
static void source_scratch_write(void *opaque,uint32_t address,uint32_t width,uint32_t value,uint32_t *fault){
 __CPROVER_assert(!source_environment->released,"tail-source-no-use-after-release");
 spx_mutable_write(opaque,address,width,value,fault);
}
static spx_ref_v5 copy_contract(void *opaque,const spx_view_v5 *destination,const spx_view_v5 *source){
 struct environment *e=opaque;
 __CPROVER_assert(same_view(destination,e->text_view) && same_view(source,e->scratch_view),"tail-copy-views");
 transition(e,1U,e->text,e->scratch,0U,0U);return destination->base;
}
static uint32_t release_contract(void *opaque,spx_ref_v5 value){
 struct environment *e=opaque;__CPROVER_assert(same_reference(value,e->scratch_view->base),"tail-release-reference");
 return transition(e,2U,e->scratch,0U,0U,0U);
}
static spx_view_v5 resource_contract(void *opaque,uint32_t id){
 struct environment *e=opaque;transition(e,3U,id,0U,0U,0U);return e->resource;
}
static uint32_t message_contract(void *opaque,uint32_t window,const spx_view_v5 *message,const spx_view_v5 *caption,uint32_t flags){
 struct environment *e=opaque;__CPROVER_assert(same_view(message,&e->resource) && same_view(caption,e->caption_view),"tail-message-views");
 return transition(e,4U,window,RESOURCE,CAPTION,flags);
}
static uint32_t focus_contract(void *opaque,uint32_t window){struct environment *e=opaque;return transition(e,5U,window,0U,0U,0U);}
spx_call_status spx_invoke_call(spx_runtime *runtime,const spx_call_event *event,const spx_machine_state *input,spx_machine_state *output){
 struct machine *m=runtime->context;struct environment *e=m->env;uint32_t fault=0,kind=0,arity=0,a=0,b=0,c=0,d=0,result=0;
 __CPROVER_assert(event->call_index==0U && event->arguments==0 && event->argument_count==0U,"tail-native-event");
 if(event->source_rva==@COPY_ENTRY@U){kind=1U;arity=2U;__CPROVER_assert(event->instruction_rva==@COPY_INSTRUCTION@U && event->return_rva==@COPY_SUCCESSOR@U,"tail-copy-site");}
 if(event->source_rva==@RELEASE_ENTRY@U){kind=2U;arity=1U;__CPROVER_assert(event->instruction_rva==@RELEASE_INSTRUCTION@U && event->return_rva==@RELEASE_SUCCESSOR@U,"tail-free-site");}
 if(event->source_rva==@RESOURCE_TEXT_ENTRY@U){kind=3U;arity=1U;result=RESOURCE;__CPROVER_assert(event->instruction_rva==@RESOURCE_TEXT_INSTRUCTION@U && event->return_rva==@RESOURCE_TEXT_SUCCESSOR@U && event->target_rva==@SUPPLIER_ENTRY@U,"tail-resource-site");}
 if(event->source_rva==@MESSAGE_ENTRY@U){kind=4U;arity=4U;__CPROVER_assert(event->instruction_rva==@MESSAGE_INSTRUCTION@U && event->return_rva==@MESSAGE_SUCCESSOR@U,"tail-message-site");}
 if(event->source_rva==@FOCUS_ENTRY@U){kind=5U;arity=1U;__CPROVER_assert(event->instruction_rva==@FOCUS_INSTRUCTION@U && event->return_rva==@FOCUS_SUCCESSOR@U,"tail-focus-site");}
 __CPROVER_assert(kind && event->kind==(kind==3U?SPX_CALL_INTERNAL_DIRECT:SPX_CALL_EXTERNAL_IMPORT),"tail-native-call-kind");
 a=machine_read(m,input->esp,4U,&fault);__CPROVER_assert(!fault,"tail-argument-a");
 if(arity>=2U){b=machine_read(m,input->esp+4U,4U,&fault);__CPROVER_assert(!fault,"tail-argument-b");}
 if(arity>=3U){c=machine_read(m,input->esp+8U,4U,&fault);__CPROVER_assert(!fault,"tail-argument-c");}
 if(arity>=4U){d=machine_read(m,input->esp+12U,4U,&fault);__CPROVER_assert(!fault,"tail-argument-d");}
 result=transition(e,kind,a,b,c,d);
 if(kind==1U)result=e->text;
 if(kind==3U)result=RESOURCE;
 *output=*input;output->eax=result;
 if(kind==3U){
  __CPROVER_assert(input->esp==m->stack-28U,"tail-resource-checked-entry-stack");
@SUPPLIER_LIVE_WORDS@
  /* Adapter return word plus the supplier's declared private writes. */
  m->word_7=event->return_rva;
  {uint32_t value; m->word_0=value;}
  {uint32_t value; m->word_1=value;}
  {uint32_t value; m->word_2=value;}
  {uint32_t value; m->word_3=value;}
  {uint32_t value; m->word_4=value;}
  {uint32_t value; m->word_5=value;}
  {uint32_t value; m->word_6=value;}
@SUPPLIER_CLOBBERS@
  return SPX_CALL_OK;
 }
 uint32_t ecx,edx;_Bool cf,zf,sf,of,pf;output->ecx=ecx;output->edx=edx;output->cf=cf;output->zf=zf;output->sf=sf;output->of=of;output->pf=pf;
 if(kind!=3U)output->esp+=4U*arity;
 spx_sync_eflags(output);return SPX_CALL_OK;
}
void check_iteration(void){
 uint32_t text_address,text_extent,scratch_address,scratch_extent,stack,input,output,removed,arbitrary_probe;probe=arbitrary_probe;
 initial_scratch=scratch_address;initial_extent=scratch_extent;initial_output=output;
@PUBLIC_DOMAIN@
 __CPROVER_assume(stack>=60U && (uint64_t)stack+16U<=UINT64_C(4294967296));
 __CPROVER_assume((uint64_t)stack+16U<=text_address || (uint64_t)text_address+text_extent<=stack-60U);
 __CPROVER_assume((uint64_t)stack+16U<=scratch_address || (uint64_t)scratch_address+scratch_extent<=stack-60U);
 __CPROVER_assume((uint64_t)stack+16U<=@IMAGE_BASE@U || stack-60U>=@IMAGE_END@U);
 __CPROVER_assume((uint64_t)text_address+text_extent<=@IMAGE_BASE@U || text_address>=@IMAGE_END@U);
 __CPROVER_assume((uint64_t)scratch_address+scratch_extent<=@IMAGE_BASE@U || scratch_address>=@IMAGE_END@U);
 struct spx_mutable_world left={0},right={0};
 struct environment a={.world=&left,.side=0U,.text=text_address,.text_extent=text_extent,.scratch=scratch_address,.scratch_extent=scratch_extent};
 struct environment b={.world=&right,.side=1U,.text=text_address,.text_extent=text_extent,.scratch=scratch_address,.scratch_extent=scratch_extent};
 struct machine memory;__CPROVER_havoc_object(&memory);memory.env=&a;memory.stack=stack;memory.word_15=removed;
 uint32_t saved_esi=memory.word_11,saved_ebx=memory.word_12,saved_ebp=memory.word_17,return_word=memory.word_18;
 spx_runtime runtime={.context=&memory,.read=machine_read,.write=machine_write,.image_base=@IMAGE_BASE@U};
 spx_machine_state initial,state;initial.esp=stack-16U;initial.ebp=stack+8U;initial.edi=text_address;initial.ebx=scratch_address;initial.esi=input;initial.ecx=output;state=initial;
 spx_step_result step;uint32_t next=@ENTRY_RVA@U;
 for(;;){step=@ORIGINAL_FUNCTION@(&runtime,&state,next);if(step.kind==SPX_RETURN || step.kind==SPX_MEMORY_FAULT)break;
  __CPROVER_assert(step.kind==SPX_BRANCH || step.kind==SPX_JUMP || step.kind==SPX_FALLTHROUGH,"tail-native-step");next=step.target_rva;}
 struct spx_mutable_domain td={&right,text_address,text_extent,3U},sd={&right,scratch_address,scratch_extent,3U},id={&right,@IMAGE_BASE@U,@IMAGE_SIZE@U,3U};
 spx_runtime tr={.context=&td,.read=spx_mutable_read,.write=spx_mutable_write},sr={.context=&sd,.read=spx_mutable_read,.write=source_scratch_write},ir={.context=&id,.read=spx_mutable_read,.write=spx_mutable_write};
 spx_component_view_context tc={&tr,text_address,text_extent,3U},sc={&sr,scratch_address,scratch_extent,3U},mc={&ir,RESOURCE,@RESOURCE_EXTENT@U,3U},cc={&ir,CAPTION,@CAPTION_EXTENT@U,1U},wc={&ir,WINDOW,4U,1U},ec={&ir,EDIT,4U,1U},nc={&ir,SUPPRESS,4U,1U};
 spx_view_v5 text={.base={1U,1U,1U,0U,text_extent,3U},.extent=text_extent,.element_width=1U,.context=&tc,.access_context=&tc,.read_u8=spx_component_view_read,.write_u8=spx_component_view_write,.read=spx_component_view_read_span,.write=spx_component_view_write_span};
 spx_view_v5 scratch={.base={1U,2U,1U,0U,scratch_extent,3U},.extent=scratch_extent,.element_width=1U,.context=&sc,.access_context=&sc,.read_u8=spx_component_view_read,.write_u8=spx_component_view_write,.read=spx_component_view_read_span,.write=spx_component_view_write_span};
 b.resource=(spx_view_v5){.base={@RESULT_REFERENCE@},.extent=@RESOURCE_EXTENT@U,.element_width=1U,.context=&mc,.access_context=&mc,.read=spx_component_view_read_span};
 spx_view_v5 caption={.base={1U,4U,1U,0U,@CAPTION_EXTENT@U,1U},.extent=@CAPTION_EXTENT@U,.element_width=1U,.context=&cc,.access_context=&cc,.read=spx_component_view_read_span};
 spx_view_v5 window={.base={1U,5U,1U,0U,4U,1U},.extent=4U,.element_width=1U,.context=&wc,.access_context=&wc,.read=spx_component_view_read_span};
 spx_view_v5 edit={.base={1U,6U,1U,0U,4U,1U},.extent=4U,.element_width=1U,.context=&ec,.access_context=&ec,.read=spx_component_view_read_span};
 spx_view_v5 notice={.base={1U,7U,1U,0U,4U,1U},.extent=4U,.element_width=1U,.context=&nc,.access_context=&nc,.read=spx_component_view_read_span};
 b.text_view=&text;b.scratch_view=&scratch;b.caption_view=&caption;source_environment=&b;
 spx_text_cleanup_services_v5 services={.context=&b,.copy=copy_contract,.release=release_contract,.resource_text=resource_contract,.message=message_contract,.focus=focus_contract};
 spx_text_cleanup_context_v5 context={.services=&services};spx_cut.input=input;spx_cut.output=output;spx_cut.removed=removed;spx_cut.scratch=scratch;
 uint32_t result=@SOURCE_CALL@;
 __CPROVER_assert((step.kind==SPX_MEMORY_FAULT)==(result==UINT32_MAX),"tail-fault-correspondence");
 __CPROVER_assert(a.count==b.count && a.released==b.released,"tail-complete-service-trace");
 __CPROVER_assert(spx_mutable_byte(&left,probe)==spx_mutable_byte(&right,probe),"tail-whole-post-memory");
 if(result!=UINT32_MAX){
  __CPROVER_assert(step.kind==SPX_RETURN && state.eax==result && result==removed,"tail-return-value");
  __CPROVER_assert(state.esp==stack+16U && state.esi==saved_esi && state.ebx==saved_ebx && state.ebp==saved_ebp && step.value==return_word,"tail-return-frame");
 }
 uint32_t continuation_slot,continuation_byte;__CPROVER_assume(continuation_slot<8U && continuation_byte<10U);
 __CPROVER_assert(state.edi == initial.edi && state.x87_control == initial.x87_control && state.x87_status == initial.x87_status && state.x87_pending_exception == initial.x87_pending_exception && state.x87_last_opcode == initial.x87_last_opcode && state.x87_instruction_pointer == initial.x87_instruction_pointer && state.x87_code_selector == initial.x87_code_selector && state.x87_data_pointer == initial.x87_data_pointer && state.x87_data_selector == initial.x87_data_selector && state.fs_base == initial.fs_base && state.x87_stack[continuation_slot].value_bytes[continuation_byte] == initial.x87_stack[continuation_slot].value_bytes[continuation_byte] && state.x87_stack[continuation_slot].empty == initial.x87_stack[continuation_slot].empty && state.x87_stack[continuation_slot].tag == initial.x87_stack[continuation_slot].tag,"tail-preserved-machine-state");
}
'''
