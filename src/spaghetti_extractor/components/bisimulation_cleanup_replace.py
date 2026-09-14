"""Guarded real UI consumer with opaque cleanup and following service effects."""
from .bisimulation_mutable_memory import sparse_mutable_memory_runtime
from .machine_overlay_v5 import _view_runtime_helpers
from .capabilities import spx_portable_reference_runtime_v5_source

PROFILE = 'cleanup-replace-paired-operation-v1'
ENTRY = 'check_replace'
INTERFACE_SHA256 = '91261e7a253cb71a7e97f2c8c937c6e7f52825af8bba283dcd26073d5fbb88db'


def render_cleanup_replace_model(contract, symbol):
    c=contract
    premises=list(c['input_relation']['caller_requirements'].values())+c['input_relation']['entry_admission']
    views=[('text','text_address','text_extent',3),('notice','4263788U','4U',1),
        ('window','4260180U','4U',1),('edit','4260184U','4U',1),('caption','4252580U','500U',1)]
    model='\n'.join(['#include "behavioral-c.h"','#include "portable-component-implementation.h"',
        *sparse_mutable_memory_runtime(2),*_view_runtime_helpers(need_read=True,need_write=True),spx_portable_reference_runtime_v5_source()])+r'''
struct environment { uint32_t side; struct spx_mutable_world *world; spx_view_v5 views[5]; };
struct machine { struct environment *env; uint32_t esp, arguments[4], writes; };
static uint32_t cleanup_calls[2],message_calls[2],seen_cleanup,seen_message;
static uint32_t text_address,text_extent,private_low,private_high,call_probe,probe;
static uint32_t shared_removed,shared_fault,shared_message,call_text,call_window,call_message,call_wparam;
static uint8_t cleanup_byte,message_byte;
static spx_view_v5 expected_views[5];
static uint32_t word(const struct spx_mutable_world *w,uint32_t a){
 uint32_t v=0;for(uint32_t i=0;i<4U;i++)v|=(uint32_t)spx_mutable_byte(w,a+i)<<(8U*i);return v;
}
static uint32_t public_address(uint32_t a){return a<private_low || a>=private_high;}
static void same_view(const spx_view_v5 *a,const spx_view_v5 *b){
 __CPROVER_assert(a->base.domain==b->base.domain && a->base.object==b->base.object &&
  a->base.generation==b->base.generation && a->base.offset==b->base.offset && a->base.extent==b->base.extent &&
  a->base.permissions==b->base.permissions && a->extent==b->extent && a->element_width==b->element_width &&
  a->context==b->context && a->access_context==b->access_context && a->read_u8==b->read_u8 &&
  a->write_u8==b->write_u8 && a->read==b->read && a->write==b->write,"replace-complete-view-arguments");
}
static uint32_t cleanup_transition(struct environment *e,uint32_t text){
 __CPROVER_assert(e->side<=1U,"replace-proof-side");
 __CPROVER_assert(cleanup_calls[e->side]++==0U && message_calls[e->side]==0U,"replace-cleanup-order");
 __CPROVER_assert(e->world->count==0U,"replace-no-writes-before-cleanup");
 if(!e->side){call_text=text;cleanup_byte=spx_mutable_byte(e->world,call_probe);seen_cleanup=1U;}
 else{
  __CPROVER_assert(seen_cleanup && text==call_text,"replace-cleanup-text");
  if(public_address(call_probe))__CPROVER_assert(spx_mutable_byte(e->world,call_probe)==cleanup_byte,"replace-cleanup-current-memory");
 }
 spx_mutable_event(e->world,0U,UINT64_C(4294967296),0U,1U,0U);
 return shared_fault?UINT32_MAX:shared_removed;
}
static uint32_t message_transition(struct environment *e,uint32_t window,uint32_t message,uint32_t wparam,uint32_t text){
 __CPROVER_assert(e->side<=1U,"replace-message-proof-side");
 __CPROVER_assert(message_calls[e->side]++==0U,"replace-one-message");
 if(!e->side){call_window=window;call_message=message;call_wparam=wparam;call_text=text;
  message_byte=spx_mutable_byte(e->world,call_probe);seen_message=1U;}
 else{
  __CPROVER_assert(seen_message && cleanup_calls[1]==cleanup_calls[0],"replace-service-prefix");
  __CPROVER_assert(window==call_window && message==call_message && wparam==call_wparam && text==call_text,"replace-message-arguments");
  if(public_address(call_probe))__CPROVER_assert(spx_mutable_byte(e->world,call_probe)==message_byte,"replace-message-current-memory");
  __CPROVER_assert(e->world->count==cleanup_calls[1],"replace-no-authored-public-writes");
 }
 /* Named returning service relation: arbitrary corresponding public post-memory
  * and every uint32 result. Reentrancy, nonreturn and invocation faults are not
  * qualified by this local profile. No NUL postcondition is inferred from cleanup. */
 spx_mutable_event(e->world,0U,UINT64_C(4294967296),0U,1U,1U);
 return shared_message;
}
static uint32_t source_cleanup(void *opaque,const spx_view_v5 *text,const spx_view_v5 *notice,
 const spx_view_v5 *window,const spx_view_v5 *edit,const spx_view_v5 *caption){
 struct environment *e=opaque;const spx_view_v5 *args[5]={text,notice,window,edit,caption};
 for(uint32_t i=0;i<5U;i++)same_view(args[i],&expected_views[i]);
 return cleanup_transition(e,text_address);
}
static uint32_t source_message(void *opaque,uint32_t window,uint32_t message,uint32_t wparam,const spx_view_v5 *text){
 same_view(text,&expected_views[0]);return message_transition(opaque,window,message,wparam,text_address);
}
static uint32_t read_machine(void *opaque,uint32_t address,uint32_t width,uint32_t *fault){
 struct machine *m=opaque;
 __CPROVER_assert(width==4U && (address==m->esp+48U || address==4260184U),"replace-readable-frame");
 *fault=0U;return word(m->env->world,address);
}
static void write_machine(void *opaque,uint32_t address,uint32_t width,uint32_t value,uint32_t *fault){
 struct machine *m=opaque;
 __CPROVER_assert(width==4U && (address==m->esp-4U || address==m->esp-8U || address==m->esp-12U || address==m->esp-16U),"replace-private-argument-frame");
 /* The admitted private words cannot alias any source view or mode storage.
  * Keep their values outside public write history; check every original push. */
 for(uint32_t i=0;i<4U;i++)if(address==m->esp-4U*(i+1U))m->arguments[i]=value;
 m->writes++;*fault=0U;
}
spx_call_status spx_invoke_call(spx_runtime *rt,const spx_call_event *ev,const spx_machine_state *input,spx_machine_state *output){
 struct machine *m=rt->context;spx_machine_state arbitrary;*output=arbitrary;
 __CPROVER_assert(ev->call_index==0U && ev->argument_count==0U && ev->stack_input_count==0U,"replace-call-event-shape");
 if(ev->kind==SPX_CALL_INTERNAL_DIRECT){
  __CPROVER_assert(ev->source_rva==0xb19cU && ev->instruction_rva==0xb19cU && ev->target_rva==0x55b7U && ev->return_rva==0xb1a1U,"replace-cleanup-edge");
  __CPROVER_assert(input->esp==m->esp && input->edi==text_address && input->df<=1U,"replace-cleanup-entry");
  uint32_t result=cleanup_transition(m->env,input->edi);
  if(shared_fault)return SPX_CALL_MEMORY_FAULT;
  output->eax=result;output->esp=input->esp;
'''
    for equality in c['normal_return']['preserved_equalities']:
        field=equality.split('==')[0].removeprefix('state.')
        if '[' not in field:model+=f'  output->{field}=input->{field};\n'
    model+='  for(uint32_t continuation_slot=0;continuation_slot<8U;continuation_slot++){\n'
    for equality in c['normal_return']['preserved_equalities']:
        field=equality.split('==')[0].removeprefix('state.')
        if '[continuation_slot]' in field:
            prefix='for(uint32_t continuation_byte=0;continuation_byte<10U;continuation_byte++)' if '[continuation_byte]' in field else ''
            model+=f'   {prefix}output->{field}=input->{field};\n'
    model+='  }\n }else{\n'
    for field,value in [('dll','user32.dll'),('symbol','SendMessageA')]:
        condition=' && '.join(f'ev->{field}[{i}]=={ord(ch)}' for i,ch in enumerate(value+'\0'))
        model+=f'  __CPROVER_assert(ev->{field} && {condition},"replace-message-{field}");\n'
    model+=r'''
  __CPROVER_assert(ev->kind==SPX_CALL_EXTERNAL_IMPORT && ev->source_rva==0xb1afU && ev->instruction_rva==0xb1afU &&
   ev->target_rva==0U && ev->return_rva==0xb1b5U && input->esp==m->esp-16U,"replace-message-edge-and-stack");
  __CPROVER_assert(m->writes==4U,"replace-complete-private-arguments");
  uint32_t window=m->arguments[3],message=m->arguments[2],wparam=m->arguments[1],text=m->arguments[0];
  __CPROVER_assert(message==194U && wparam==1U && text==text_address,"replace-message-native-arguments");
  output->eax=message_transition(m->env,window,message,wparam,text);
  output->esp=input->esp+16U;output->ebp=input->ebp;output->ebx=input->ebx;output->edi=input->edi;output->esi=input->esi;
 }
 return SPX_CALL_OK;
}
void check_replace(void){
 uint32_t p,q,address,extent,r,f,message,mode;
 probe=p;call_probe=q;text_address=address;text_extent=extent;shared_removed=r;shared_fault=f;shared_message=message;
 __CPROVER_assume(r!=UINT32_MAX && f<=1U);
 spx_machine_state initial,state;
 __CPROVER_assume(initial.esp>=16U && (uint64_t)initial.esp+52U<=UINT64_C(4294967296));
 __CPROVER_assume(initial.edi==text_address && initial.df<=1U);
 __CPROVER_assume(text_address>0U && text_extent>0U && (uint64_t)text_address+text_extent<=UINT64_C(4294967296));
 uint32_t active=(mode!=2U && mode!=3U),stack=initial.esp-4U;
 private_low=initial.esp-16U;private_high=initial.esp;
 __CPROVER_assume((uint64_t)text_address+text_extent<=private_low || text_address>=private_high);
 __CPROVER_assume(private_high<=4194304U || private_low>=4419584U);
 struct spx_mutable_world left={0},right={0};
 __CPROVER_assume(word(&left,initial.esp+48U)==mode);
 if(active){
  uint32_t length,length_target,scratch_address,scratch_extent;
'''
    model+='\n'.join('  __CPROVER_assume('+v+');' for v in premises)+'\n'
    model+=r'''
  __CPROVER_assume(word(&left,4251992U)==length_target);
  private_low=initial.esp-76U;
 }
 struct environment env_left={.side=0U,.world=&left},env_right={.side=1U,.world=&right};
'''
    for i,(name,address,extent,permission) in enumerate(views):
        model+=f''' struct spx_mutable_domain d_{name}={{&right,{address},{extent},{permission}U}};
 spx_runtime rt_{name}={{.context=&d_{name},.read=spx_mutable_read,.write=spx_mutable_write}};
 spx_component_view_context v_{name}={{&rt_{name},{address},{extent},{permission}U}};
 env_right.views[{i}]=(spx_view_v5){{.base={{1U,{i+1}U,1U,0U,{extent},{permission}U}},.extent={extent},.element_width=1U,
  .context=&v_{name},.access_context=&v_{name},.read_u8=spx_component_view_read,.write_u8=spx_component_view_write,
  .read=spx_component_view_read_span,.write=spx_component_view_write_span}};
 expected_views[{i}]=env_right.views[{i}];
'''
    model+=r'''
 struct machine m={&env_left,initial.esp};spx_runtime rt={.context=&m,.read=read_machine,.write=write_machine,.image_base=4194304U};
 state=initial;spx_step_result step=spx_sub_0000b18e(&rt,&state,0xb18eU);
 spx_cleanup_replace_services_v5 services={.context=&env_right,.cleanup=source_cleanup,.send_message=source_message};
 spx_cleanup_replace_context_v5 context={.services=&services};
 spx_outcome_v5 result=@SOURCE_SYMBOL@(&context,&env_right.views[0],&env_right.views[1],&env_right.views[2],
  &env_right.views[3],&env_right.views[4],mode);
 __CPROVER_assert(context.services==&services && context.protocol_state==SPX_CLEANUP_REPLACE_PROTOCOL_READY && context.state.reserved==0U &&
  services.context==&env_right && services.cleanup==source_cleanup && services.send_message==source_message,"replace-source-context-frame");
 for(uint32_t i=0;i<5U;i++)same_view(&env_right.views[i],&expected_views[i]);
 __CPROVER_assert(cleanup_calls[0]==active && cleanup_calls[1]==active,"replace-both-mode-guards");
 if(active && shared_fault){
  __CPROVER_assert(step.kind==SPX_MEMORY_FAULT && result.fault==1U,"replace-cleanup-fault");
  __CPROVER_assert(message_calls[0]==0U && message_calls[1]==0U && left.count==1U && right.count==1U && m.writes==0U,"replace-fault-prefix");
 }else{
  __CPROVER_assert(step.kind==SPX_FALLTHROUGH && step.target_rva==0xb1b5U && result.fault==0U,"replace-normal-continuation");
  __CPROVER_assert(state.eax==result.value && result.value==shared_message,"replace-complete-message-result");
  __CPROVER_assert(message_calls[0]==1U && message_calls[1]==1U && left.count==active+1U && right.count==active+1U && m.writes==4U,"replace-message-count-and-write-frame");
  __CPROVER_assert(state.esp==initial.esp && state.ebp==initial.ebp && state.ebx==initial.ebx && state.edi==initial.edi && state.esi==initial.esi,"replace-normal-register-frame");
 }
 if(public_address(probe))__CPROVER_assert(spx_mutable_byte(&left,probe)==spx_mutable_byte(&right,probe),"replace-current-post-memory");
}
'''
    return model.replace('@SOURCE_SYMBOL@',symbol)
