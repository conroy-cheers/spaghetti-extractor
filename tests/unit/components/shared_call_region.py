"""Actual caller cuts compose an opaque paired shared transition.

The caller must supply a validated conditional original/source transition.
This test renderer is not a qualification rule. It checks two retained call
regions and their live successors, not whole caller reachability or MessageBox.
"""

import json
from pathlib import Path

from spaghetti_extractor.components.bisimulation_mutable_memory import sparse_mutable_memory_runtime
from spaghetti_extractor.components.bisimulation_clobber_frame import frame_equalities
from spaghetti_extractor.components.bisimulation_harness import _architectural_state_equalities
from spaghetti_extractor.components.machine_overlay_v5 import _view_runtime_helpers
from spaghetti_extractor.components.capabilities import spx_portable_reference_runtime_v5_source
from spaghetti_extractor.artifacts.artifact_set import canonical_sha256_v3

FIXTURE = Path(__file__).parents[2]/'fixtures/metapad-resource-callers'


def render_call_regions(transition):
    """The implementation/evidence digest never enters the consumer C model.

    One abstract event per dependency call represents every framed final memory.
    Related calls must have equal IDs and related readable input bytes. Matched
    child effects remain an explicit premise of the checked functional supplier;
    this renderer does not invent or enumerate them as external service calls.
    """
    domain = transition['domain']
    if (transition['authorizing'] is not False or transition['runtime_compatibility'] != 'unverified'
            or transition['domain_sha256'] != canonical_sha256_v3(domain)
            or transition['operation_id'] != 'get'):
        raise ValueError('caller needs a bound conditional shared transition')
    machine = domain['machine_domain']
    if (machine['image_base'] != 4194304 or machine['image_size'] != 225280
            or machine['private_accesses'] != [{'offset':-28,'bytes':36}]
            or machine['private_writes'] != [{'offset':-28,'bytes':28}]):
        raise ValueError('caller child stack/image domain differs')
    operation = domain['binding_intent']['operations'][0]
    if operation['entry_rvas'] != [0x1284]:
        raise ValueError('caller targets another original operation')
    # This consumer has manually selected concrete image bindings. Changing any
    # projection requires a new caller-admission check, not signature matching.
    projection = operation['machine_projection']['operation']
    states = {row['id']:row['entry'] for row in projection['state']}
    if (states['module']['base']['value'] != 0x410150 or states['module']['extent']['value'] != 4
            or states['buffer']['base']['value'] != 0x413d20 or states['buffer']['extent']['value'] != 500
            or projection['parameters'][0]['projection'] != {'kind':'stack','width':32,'offset':4,'at':'entry'}):
        raise ValueError('caller child input projections differ')
    metadata = json.loads((FIXTURE/'boundary.json').read_text())
    if (domain['exact_c_slice_sha256'] != metadata['supplier_exact_c_slice_sha256']
            or domain['binding_intent']['intent_sha256'] != metadata['supplier_binding_intent_sha256']
            or canonical_sha256_v3(domain['runtime_contract']) != metadata['supplier_runtime_contract_sha256']
            or machine['clobbers'] != ['cf','df','ecx','edx','eflags','of','pf','sf','zf']):
        raise ValueError('caller needs its original supplier and fixed continuation frame')
    entries = {row['entry_rva']:row['calls'][0] for row in metadata['regions']}
    assert set(entries) == {0x5646,0x570e}
    preserved = frame_equalities(_architectural_state_equalities('state','initial'),
                                [*machine['clobbers'],'eax','esp'])
    source = ['#include "behavioral-c.h"', '#include "portable-component-implementation.h"',
        *sparse_mutable_memory_runtime(6), *_view_runtime_helpers(need_read=True,need_write=True),
        spx_portable_reference_runtime_v5_source(), '''
struct caller_environment {
  uint32_t side;
  struct spx_mutable_world *world;
  spx_view_v5 buffer;
};
struct caller_machine {
  struct caller_environment *environment;
  uint32_t entry;
  uint32_t argument, caption, flags, local;
};
static struct {uint32_t count[2], id[2]; uint8_t before[2];} child_trace;
static uint32_t probe;
static spx_view_v5 shared_transition(void *opaque, uint32_t id) {
  struct caller_environment *env=opaque;
  uint32_t position=child_trace.count[env->side]++;
  __CPROVER_assert(position<2U,"caller-dependency-count-capacity");
  __CPROVER_assume(position<2U);
  if (!env->side) {
    child_trace.id[position]=id;
    child_trace.before[position]=spx_mutable_byte(env->world,probe);
  } else {
    __CPROVER_assert(id==child_trace.id[position],"caller-dependency-arguments");
    if ((probe>=0x410150U && probe<0x410154U) || (probe>=0x413d20U && probe<0x413f14U))
      __CPROVER_assert(spx_mutable_byte(env->world,probe)==child_trace.before[position],
          "caller-dependency-current-input-memory");
  }
  spx_mutable_event(env->world,0x413d20U,500U,0U,1U,position);
  return env->buffer;
}
static uint32_t machine_read(void *opaque,uint32_t address,uint32_t width,uint32_t *fault) {
  struct caller_machine *machine=opaque;
  __CPROVER_assert(width==4U,"caller-access-width");
  *fault=0;
  if(address==machine->entry-12U) return machine->argument;
  if(address==machine->entry-8U) return machine->caption;
  if(address==machine->entry-4U) return machine->flags;
  if(address==machine->entry) return machine->local;
  __CPROVER_assert(0,"caller-private-read-frame"); *fault=1U; return 0U;
}
static void machine_write(void *opaque,uint32_t address,uint32_t width,uint32_t value,uint32_t *fault) {
  struct caller_machine *machine=opaque;
  __CPROVER_assert(width==4U,"caller-access-width");
  if(address==machine->entry-12U) machine->argument=value;
  else if(address==machine->entry-8U) machine->caption=value;
  else if(address==machine->entry-4U) machine->flags=value;
  else __CPROVER_assert(0,"caller-private-write-frame");
  *fault=0;
}
spx_call_status spx_invoke_call(spx_runtime *runtime,const spx_call_event *event,
    const spx_machine_state *input,spx_machine_state *output) {
  struct caller_machine *machine=runtime->context;
  uint32_t fault=0U;
  __CPROVER_assert(event->kind==SPX_CALL_INTERNAL_DIRECT && event->target_rva==0x1284U &&
      event->call_index==0U && event->arguments==0 && event->argument_count==0U &&
      event->stack_input_count==1U && event->stack_inputs!=0,"caller-dependency-event");
  __CPROVER_assert(event->stack_inputs[0].offset==0U && event->stack_inputs[0].width==4U,
      "caller-dependency-stack-capture");
''']
    conditions = ['(event->source_rva==%dU && event->instruction_rva==%dU && event->return_rva==%dU)' %
        (entry,call['instruction_rva'],call['return_rva']) for entry,call in sorted(entries.items())]
    source += ['  __CPROVER_assert('+' || '.join(conditions)+',"caller-dependency-control-edge");', '''
  __CPROVER_assert(input->esp==machine->entry-12U,"caller-dependency-entry-stack");
  uint32_t id=machine_read(machine,input->esp,4U,&fault);
  __CPROVER_assert(!fault && id==event->stack_inputs[0].value,"caller-dependency-stack-value");
  spx_view_v5 value=shared_transition(machine->environment,id);
  (void)value;
  *output=*input;
  output->eax=0x413d20U;
  /* The checked supplier's private writes and the adapter's return word lie
   * strictly below the three live caller words. No private byte in that range
   * can be read by this caller region: the memory callbacks assert its exact
   * word footprint. No value from the callee's private frame is transported. */
''']
    for field in machine['clobbers']:
        source.append(f'  {{uint32_t arbitrary; output->{field}=arbitrary;}}')
    source += ['  return SPX_CALL_OK;','}', '''
static spx_view_v5 portable_region(void *opaque,uint32_t which) {
  /* Proof-region fragments of the two callers, not new production APIs. */
  return shared_transition(opaque,which==0U ? 31U : 32U);
}
void check_call_regions(void) {
  uint32_t arbitrary_probe; probe=arbitrary_probe;
  struct spx_mutable_world worlds[2]={{0},{0}};
  struct caller_environment envs[2];
  struct spx_mutable_domain domains[2];
  spx_runtime view_runtimes[2];
  spx_component_view_context transports[2];
  for(uint32_t side=0;side<2U;++side) {
    envs[side].side=side; envs[side].world=&worlds[side];
    domains[side]=(struct spx_mutable_domain){&worlds[side],0x413d20U,500U,3U};
    view_runtimes[side]=(spx_runtime){.context=&domains[side],.read=spx_mutable_read,.write=spx_mutable_write};
    transports[side]=(spx_component_view_context){&view_runtimes[side],0x413d20U,500U,3U};
    envs[side].buffer=(spx_view_v5){.base={1U,UINT64_C(2134217653344611032),1U,0x3d20U,18272U,3U},
      .extent=500U,.element_width=1U,.context=&transports[side],.access_context=&transports[side],
      .read_u8=spx_component_view_read,.read=spx_component_view_read_span,
      .write_u8=spx_component_view_write,.write=spx_component_view_write_span};
  }
  spx_view_v5 saved=envs[1].buffer;
  for(uint32_t side=0;side<2U;++side) {
    for(uint32_t which=0;which<2U;++which) {
      if(!side) {
        spx_machine_state initial,state;
        __CPROVER_assume(initial.esp>=44U && (uint64_t)initial.esp+4U<=UINT64_C(4294967296));
        __CPROVER_assume((uint64_t)initial.esp+4U<=4194304U || initial.esp-44U>=4419584U);
        struct caller_machine machine;
        __CPROVER_havoc_object(&machine);
        machine.environment=&envs[0]; machine.entry=initial.esp;
        uint32_t preserved_word; uint32_t fault=0U;
        preserved_word=machine_read(&machine,initial.esp,4U,&fault);
        spx_runtime runtime={.context=&machine,.read=machine_read,.write=machine_write,.image_base=4194304U};
        state=initial;
        spx_step_result result=which==0U ? spx_sub_00005646(&runtime,&state,0x5646U)
                                          : spx_sub_0000570e(&runtime,&state,0x570eU);
        __CPROVER_assert(result.kind==SPX_FALLTHROUGH && result.target_rva==(which==0U ? 0x5654U : 0x571cU),
            "caller-actual-successor");
        __CPROVER_assert(state.esp==initial.esp-12U && state.eax==0x413d20U,"caller-live-register-transport");
        __CPROVER_assert(machine_read(&machine,state.esp,4U,&fault)==(which==0U ? 31U : 32U) &&
            machine_read(&machine,state.esp+4U,4U,&fault)==0x40e3a4U &&
            machine_read(&machine,state.esp+8U,4U,&fault)==48U,"caller-live-stack-transport");
        __CPROVER_assert(machine_read(&machine,initial.esp,4U,&fault)==preserved_word,"caller-private-complement");
        uint32_t continuation_slot,continuation_byte;
        __CPROVER_assume(continuation_slot<8U && continuation_byte<10U);
''', '        __CPROVER_assert('+' && '.join(preserved)+',"caller-preserved-register-frame");', '''
      } else {
        spx_view_v5 result=portable_region(&envs[1],which);
        __CPROVER_assert(result.base.object==saved.base.object && result.base.offset==saved.base.offset &&
            result.access_context==saved.access_context && result.extent==500U,"caller-logical-result-alias");
      }
    }
  }
  __CPROVER_assert(child_trace.count[0]==2U && child_trace.count[1]==2U,"caller-dependency-call-count");
  __CPROVER_assert(spx_mutable_byte(&worlds[0],probe)==spx_mutable_byte(&worlds[1],probe),"caller-paired-post-memory");
  uint32_t offset; uint8_t byte;
  __CPROVER_assume(offset<500U);
  __CPROVER_assert(spx_view_read_u8(&saved,offset,&byte)==0U && byte==spx_mutable_byte(&worlds[1],0x413d20U+offset),
      "caller-old-alias-current-contents");
}
''']
    rendered = '\n'.join(source)
    # Separate world objects avoid whole-array-of-struct updates in the pinned
    # SMT array backend. This unrolls two fixed harness sides, not application
    # control flow or the supplier's implementation.
    variables = {'worlds':'struct spx_mutable_world', 'envs':'struct caller_environment',
        'domains':'struct spx_mutable_domain', 'view_runtimes':'spx_runtime',
        'transports':'spx_component_view_context'}
    for name, typ in variables.items():
        initializer = '={{0},{0}}' if name == 'worlds' else ''
        replacement = f'{typ} {name}_left'+('={0}' if name=='worlds' else '')+f', {name}_right'+('={0}' if name=='worlds' else '')+';'
        rendered = rendered.replace(f'{typ} {name}[2]{initializer};', replacement)
    loop = 'for(uint32_t side=0;side<2U;++side) {'
    while loop in rendered:
        start=rendered.index(loop); opening=start+len(loop); end=opening; depth=1
        while depth:
            depth += (rendered[end]=='{')-(rendered[end]=='}'); end+=1
        body=rendered[opening:end-1]; copies=[]
        for ordinal,side in enumerate(('left','right')):
            part=body.replace('if(!side)',f'if(!{ordinal}U)').replace('.side=side;',f'.side={ordinal}U;')
            for name in variables:
                part=part.replace(name+'[side]',name+'_'+side)
            copies.append('{'+part+'}')
        rendered=rendered[:start]+'\n'.join(copies)+rendered[end:]
    for name in variables:
        for ordinal,side in enumerate(('left','right')):
            rendered=rendered.replace(f'{name}[{ordinal}]',name+'_'+side)
    return rendered
