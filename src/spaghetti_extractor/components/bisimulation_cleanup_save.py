"""Body-free cleanup contract substitution in the real save-path consumer.

This supported paired-operation profile preserves all uint32 length values and
models the actual two outgoing argument pushes as private continuation transport.
Concrete caller/runtime applicability remains a separate conditional premise.
"""
from .bisimulation_mutable_memory import sparse_mutable_memory_runtime
from .machine_overlay_v5 import _view_runtime_helpers
from .capabilities import spx_portable_reference_runtime_v5_source

CONTRACT_SHA256 = 'e3692b0d5f10745e69eb01567f315be647a8321d8af67d39501cb9a6aa1816dd'
ENTRY = 'check_save'
PROFILE = 'cleanup-save-paired-operation-v1'


def render_cleanup_save_model(contract, symbol):
    c = contract
    # The instantiated spatial/incoming predicates are retained below. Allocation,
    # runtime and service premises remain named conditional dependencies, not tests.
    premises=list(c['input_relation']['caller_requirements'].values())+c['input_relation']['entry_admission']
    view_rows=[('text','text_address','text_extent',3),('suppress_notice','4263788U','4U',1),('main_window','4260180U','4U',1),('edit_window','4260184U','4U',1),('caption','4252580U','500U',1),('length','initial.ebp-12U','4U',3)]
    model='\n'.join(['#include "behavioral-c.h"','#include "portable-component-implementation.h"',*sparse_mutable_memory_runtime(4),*_view_runtime_helpers(need_read=True,need_write=True),spx_portable_reference_runtime_v5_source()])+r'''
    struct environment { uint32_t side, calls; struct spx_mutable_world *world; spx_view_v5 views[6]; };
    struct machine { struct environment *env; uint32_t esp,ebp; };
    static uint32_t probe,call_probe,call_text,shared_removed,shared_fault,seen;
    static uint8_t call_byte;
    static uint32_t word(const struct spx_mutable_world *w,uint32_t a) {
     uint32_t value=0; for(uint32_t i=0;i<4;i++)value|=(uint32_t)spx_mutable_byte(w,a+i)<<(8U*i); return value;
    }
    static uint32_t dependency(struct environment *e,uint32_t text) {
     __CPROVER_assert(e->calls++==0U,"save-one-cleanup-call");
     __CPROVER_assert(e->world->count==0U,"save-no-public-writes-before-cleanup");
     if(e->side==0U){call_text=text;call_byte=spx_mutable_byte(e->world,call_probe);seen=1U;}
     else {
      __CPROVER_assert(seen==1U && text==call_text,"save-cleanup-text-correspondence");
      __CPROVER_assert(spx_mutable_byte(e->world,call_probe)==call_byte,"save-cleanup-current-input-memory");
     }
     /* Abstract all public post-memory, not just the text or a guessed write frame.
      * The caller-private callee frame is never read afterward and is excluded from
      * the exported observation. Both executions start with the same byte function. */
     spx_mutable_event(e->world,0U,UINT64_C(4294967296),0U,1U,0U);
     return shared_fault?UINT32_MAX:shared_removed;
    }
    static uint32_t source_cleanup(void *opaque,const spx_view_v5 *text,const spx_view_v5 *notice,
     const spx_view_v5 *window,const spx_view_v5 *edit,const spx_view_v5 *caption) {
     struct environment *e=opaque;
     const spx_view_v5 *args[5]={text,notice,window,edit,caption};
     for(uint32_t i=0;i<5;i++) {
      const spx_view_v5 *a=args[i],*b=&e->views[i];
      __CPROVER_assert(a->base.domain==b->base.domain && a->base.object==b->base.object &&
        a->base.generation==b->base.generation && a->base.offset==b->base.offset && a->base.extent==b->base.extent &&
        a->base.permissions==b->base.permissions && a->extent==b->extent && a->element_width==b->element_width &&
        a->context==b->context && a->access_context==b->access_context && a->read_u8==b->read_u8 &&
        a->write_u8==b->write_u8 && a->read==b->read && a->write==b->write,"save-cleanup-complete-view-arguments");
     }
     struct spx_component_view_context *v=(struct spx_component_view_context *)text->access_context;
     return dependency(e,v->address);
    }
    static uint32_t read_machine(void *opaque,uint32_t address,uint32_t width,uint32_t *fault) {
     struct machine *m=opaque;
     __CPROVER_assert(width==4U && (address==m->ebp-20U || address==m->ebp-12U || address==4252140U),"save-readable-frame");
     *fault=0;return word(m->env->world,address);
    }
    static void write_machine(void *opaque,uint32_t address,uint32_t width,uint32_t value,uint32_t *fault) {
     struct machine *m=opaque;
     __CPROVER_assert(width==4U && (address==m->ebp-12U || address==m->esp-4U || address==m->esp-8U),"save-writable-frame");
     spx_mutable_event(m->env->world,address,width,value,0U,0U);*fault=0;
    }
    spx_call_status spx_invoke_call(spx_runtime *rt,const spx_call_event *ev,
     const spx_machine_state *input,spx_machine_state *output) {
     struct machine *m=rt->context;
     __CPROVER_assert(ev->kind==SPX_CALL_INTERNAL_DIRECT && ev->call_index==0U && ev->source_rva==0x5c2aU &&
      ev->instruction_rva==0x5c2fU && ev->target_rva==0x55b7U && ev->return_rva==0x5c34U &&
      ev->argument_count==0U && ev->stack_input_count==0U,"save-original-cleanup-edge");
     __CPROVER_assert(input->esp==m->esp && input->ebp==m->ebp && input->df<=1U,"save-callee-entry-transport");
     uint32_t result=dependency(m->env,input->edi);
     spx_machine_state arbitrary; *output=arbitrary;
     if(shared_fault)return SPX_CALL_MEMORY_FAULT;
     output->eax=result;output->esp=input->esp;
    '''
    # Copy only frame guarantees exported by the checked summary. Other registers,
    # including all native fault registers, remain arbitrary.
    for equality in c['normal_return']['preserved_equalities']:
     field=equality.split('==')[0].removeprefix('state.')
     if '[' not in field:model+=f' output->{field}=input->{field};\n'
    model+=' for(uint32_t continuation_slot=0;continuation_slot<8U;continuation_slot++){\n'
    for equality in c['normal_return']['preserved_equalities']:
     field=equality.split('==')[0].removeprefix('state.')
     if '[continuation_slot]' in field:
      prefix='for(uint32_t continuation_byte=0;continuation_byte<10U;continuation_byte++)' if '[continuation_byte]' in field else ''
      model+=f'  {prefix}output->{field}=input->{field};\n'
    model+=' }\n return SPX_CALL_OK;\n}\nvoid check_save(void){\n'
    model+=' uint32_t arbitrary_probe,arbitrary_call_probe;probe=arbitrary_probe;call_probe=arbitrary_call_probe;\n'
    model+=' uint32_t r,f;shared_removed=r;shared_fault=f;__CPROVER_assume(r!=UINT32_MAX && f<=1U);\n'
    model+=' spx_machine_state initial,state;uint32_t text_address,text_extent,length,length_target,scratch_address,scratch_extent;\n'
    model+=' __CPROVER_assume(initial.esp>=76U);uint32_t stack=initial.esp-4U;\n'
    model+='\n'.join(' __CPROVER_assume('+v+');' for v in premises)+'\n'
    model+=r'''
     __CPROVER_assume(initial.df<=1U);
     /* The caller's live EBP slots are outside the callee frame, outside the image,
      * and nonwrapping. No constraint on the stored uint32 text length is needed. */
     __CPROVER_assume(initial.ebp>=20U && initial.ebp-20U>=initial.esp);
     __CPROVER_assume(initial.ebp<=4194304U || initial.ebp-20U>=4419584U);
     struct spx_mutable_world left={0},right={0};
     __CPROVER_assume(word(&left,initial.ebp-20U)==text_address);
     __CPROVER_assume(word(&left,4251992U)==length_target);
     struct environment env_left={.side=0U,.world=&left},env_right={.side=1U,.world=&right};
    '''
    # Native side uses physical mappings; source views hold real generated access
    # callbacks with separate persistent context objects. Equal bytes come from the
    # shared current world, never from reconstructing the reference descriptors.
    for i,(name,address,extent,permission) in enumerate(view_rows):
     model+=f''' struct spx_mutable_domain d_{name}={{&right,{address},{extent},{permission}U}};
     spx_runtime rt_{name}={{.context=&d_{name},.read=spx_mutable_read,.write=spx_mutable_write}};
     spx_component_view_context v_{name}={{&rt_{name},{address},{extent},{permission}U}};
     env_right.views[{i}]=(spx_view_v5){{.base={{1U,{i+1}U,1U,0U,{extent},{permission}U}},.extent={extent},.element_width=1U,
      .context=&v_{name},.access_context=&v_{name},.read_u8=spx_component_view_read,.write_u8=spx_component_view_write,
      .read=spx_component_view_read_span,.write=spx_component_view_write_span}};
    '''
    model+=r'''
     struct machine m={&env_left,initial.esp,initial.ebp};
     spx_runtime rt={.context=&m,.read=read_machine,.write=write_machine,.image_base=4194304U};
     state=initial;spx_step_result step=spx_sub_00005c2a(&rt,&state,0x5c2aU);
     spx_cleanup_save_services_v5 services={.context=&env_right,.cleanup=source_cleanup};
     spx_cleanup_save_context_v5 context={.services=&services};
     uint32_t removed=@SOURCE_SYMBOL@(&context,&env_right.views[0],&env_right.views[1],&env_right.views[2],
      &env_right.views[3],&env_right.views[4],&env_right.views[5]);
     __CPROVER_assert(context.services==&services && context.protocol_state==SPX_CLEANUP_SAVE_PROTOCOL_READY &&
       context.state.reserved==0U && services.context==&env_right && services.cleanup==source_cleanup,
       "save-source-context-frame");
     __CPROVER_assert(env_left.calls==1U && env_right.calls==1U,"save-matching-cleanup-invocations");
     if(shared_fault){
      __CPROVER_assert(step.kind==SPX_MEMORY_FAULT && removed==UINT32_MAX,"save-cleanup-fault-stops-continuation");
      __CPROVER_assert(left.count==1U && right.count==1U,"save-no-post-fault-writes");
     }else{
      __CPROVER_assert(left.count==4U && right.count==2U && right.events[1].service==0U &&
        right.events[1].address==initial.ebp-12U && right.events[1].extent==4U,
        "save-normal-public-write-frame");
      __CPROVER_assert(step.kind==SPX_FALLTHROUGH && step.target_rva==0x5c3fU,"save-normal-continuation");
      __CPROVER_assert(state.eax==removed && removed==shared_removed,"save-removed-count");
      __CPROVER_assert(word(&left,initial.ebp-12U)==word(&right,initial.ebp-12U),"save-adjusted-length");
      __CPROVER_assert(state.esp==initial.esp-8U && word(&left,state.esp)==initial.ebx &&
        word(&left,state.esp+4U)==initial.ebx,"save-outgoing-argument-transport");
      __CPROVER_assert(state.edi==word(&right,4252140U) && state.esi==text_address &&
        state.ebp==initial.ebp && state.ebx==initial.ebx,"save-continuation-registers");
     }
     if((uint64_t)probe<stack-72U || (uint64_t)probe>=(uint64_t)stack+4U)
      __CPROVER_assert(spx_mutable_byte(&left,probe)==spx_mutable_byte(&right,probe),"save-current-public-post-memory");
    }
    '''
    # Header field name is supplied by the current production view implementation.
    # Production context uses the checked physical address field.
    return model.replace('@SOURCE_SYMBOL@', symbol)
