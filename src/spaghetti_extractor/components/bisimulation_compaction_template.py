"""Local current-memory iteration recipe; application statements are supplied separately."""

TEMPLATE = r'''#include "behavioral-c.h"
#include "portable-component-implementation.h"
@MEMORY_RUNTIME@
@VIEW_RUNTIME@

@OBSERVER@
#include "authored.c"
@REFERENCE_RUNTIME@

struct machine_memory {struct spx_mutable_world *world;uint32_t text,text_extent,scratch,scratch_extent,stack;@PRIVATE_DECLARATIONS@};
static uint32_t machine_read(void *opaque,uint32_t address,uint32_t width,uint32_t *fault){
 struct machine_memory *m=opaque;*fault=0U;
@PRIVATE_READS@
 __CPROVER_assert(width==1U,"loop-text-read-width");
 if(address<m->text || (uint64_t)address>=(uint64_t)m->text+m->text_extent){*fault=1U;return 0U;}
 return spx_mutable_byte(m->world,address);
}
static void machine_write(void *opaque,uint32_t address,uint32_t width,uint32_t value,uint32_t *fault){
 struct machine_memory *m=opaque;*fault=0U;
@PRIVATE_WRITES@
 __CPROVER_assert(width==1U,"loop-scratch-write-width");
 if(address<m->scratch || (uint64_t)address>=(uint64_t)m->scratch+m->scratch_extent){*fault=1U;return;}
 spx_mutable_event(m->world,address,1U,value,0U,0U);
}
spx_call_status spx_invoke_call(spx_runtime *r,const spx_call_event *e,const spx_machine_state *i,spx_machine_state *o){
 (void)r;(void)e;(void)i;(void)o;__CPROVER_assert(0,"loop-no-service-call");return SPX_CALL_UNIMPLEMENTED;
}
void check_iteration(void){
 uint32_t text_address,text_extent,scratch_address,scratch_extent,stack,input,output,removed,probe;
@PUBLIC_DOMAIN@
 __CPROVER_assume(@STACK_DOMAIN@);
 __CPROVER_assume((uint64_t)stack+@PRIVATE_EXTENT@U<=text_address || (uint64_t)text_address+text_extent<=stack);
 __CPROVER_assume((uint64_t)stack+@PRIVATE_EXTENT@U<=scratch_address || (uint64_t)scratch_address+scratch_extent<=stack);
 struct spx_mutable_world left={0},right={0};
 struct machine_memory memory={.world=&left,.text=text_address,.text_extent=text_extent,.scratch=scratch_address,.scratch_extent=scratch_extent,.stack=stack};
@PRIVATE_INITIALIZERS@
@INITIAL_STATE@
 spx_runtime runtime={.context=&memory,.read=machine_read,.write=machine_write,.image_base=@IMAGE_BASE@U};
 spx_step_result step=@ORIGINAL_FUNCTION@(&runtime,&state,@ENTRY_RVA@U);
 struct spx_mutable_domain text_domain={&right,text_address,text_extent,@TEXT_PERMISSIONS@U},scratch_domain={&right,scratch_address,scratch_extent,3U};
 spx_runtime text_runtime={.context=&text_domain,.read=spx_mutable_read@TEXT_RUNTIME_WRITE@},scratch_runtime={.context=&scratch_domain,.read=spx_mutable_read,.write=spx_mutable_write};
 spx_component_view_context text_transport={&text_runtime,text_address,text_extent,@TEXT_PERMISSIONS@U},scratch_transport={&scratch_runtime,scratch_address,scratch_extent,3U};
 spx_view_v5 text={.base={1U,1U,1U,0U,text_extent,@TEXT_PERMISSIONS@U},.extent=text_extent,.element_width=1U,.context=&text_transport,.access_context=&text_transport,.read_u8=spx_component_view_read,.read=spx_component_view_read_span@TEXT_VIEW_WRITE@};
 spx_cut.scratch=(spx_view_v5){.base={1U,2U,1U,0U,scratch_extent,3U},.extent=scratch_extent,.element_width=1U,.context=&scratch_transport,.access_context=&scratch_transport,.read_u8=spx_component_view_read,.write_u8=spx_component_view_write,.read=spx_component_view_read_span,.write=spx_component_view_write_span};
 spx_cut.input=input;spx_cut.output=output;spx_cut.removed=removed;
 observed_state=state;observed_step=step;observed_removed=memory.removed;observed_extent=text_extent;
 uint32_t result=@SOURCE_CALL@;
 __CPROVER_assert((step.kind==SPX_MEMORY_FAULT)==(result==UINT32_MAX),"loop-fault-outcome");
 __CPROVER_assert(spx_mutable_byte(&left,probe)==spx_mutable_byte(&right,probe),"loop-whole-post-memory");
 if(result!=UINT32_MAX){
@OUTGOING_DOMAIN@
  __CPROVER_assert((step.kind==SPX_BRANCH || step.kind==SPX_FALLTHROUGH || step.kind==SPX_JUMP) && step.target_rva==result,"loop-control-successor");
  if(scratch_extent && probe>=scratch_address+state.@OUTPUT_REGISTER@ && (uint64_t)probe<(uint64_t)scratch_address+scratch_extent)
   __CPROVER_assert(spx_mutable_byte(&right,probe)==0U,"loop-zero-suffix-preserved");
  __CPROVER_assert(state.@OUTPUT_REGISTER@<=state.@INPUT_REGISTER@ && memory.removed==state.@INPUT_REGISTER@-state.@OUTPUT_REGISTER@,"loop-counter-invariant");
  if(result==@ENTRY_RVA@U){
   __CPROVER_assert(state.@INPUT_REGISTER@>input && state.@INPUT_REGISTER@<text_extent,"loop-progress-and-domain");
   __CPROVER_assert((scratch_extent==0U && state.@OUTPUT_REGISTER@==0U) || (scratch_extent>0U && state.@INPUT_REGISTER@<scratch_extent),"loop-scratch-domain-preserved");
  }
 }
 uint32_t continuation_slot,continuation_byte;__CPROVER_assume(continuation_slot<8U && continuation_byte<10U);
 __CPROVER_assert(@FRAME@,"loop-preserved-register-frame");
}
'''
