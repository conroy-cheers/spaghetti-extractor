"""Paired single-call regions consume a checked borrowed-image transition.

Neither supplier implementation is emitted. Input-memory correspondence and
framed post-memory are separate; an old alias observes the current shared world.
"""

from .bisimulation_mutable_memory import sparse_mutable_memory_runtime
from .bisimulation_clobber_frame import frame_equalities
from .bisimulation_harness import _architectural_state_equalities
from .machine_overlay_v5 import _view_runtime_helpers
from .capabilities import spx_portable_reference_runtime_v5_source


ENTRY = 'spx_check_call_region'


def render_call_model(domain):
    d = domain
    words = d['stack_words']
    address, extent = d['result_address'], d['result_extent']
    position = lambda offset: f'(uint32_t)((int64_t)machine->entry + INT64_C({offset}))'
    readable = ' || '.join(f'(probe>=UINT32_C({base}) && (uint64_t)probe<UINT64_C({base+size}))'
                           for size, _, base in d['views'].values())
    source = ['#include "behavioral-c.h"', '#include "portable-component-implementation.h"',
        *sparse_mutable_memory_runtime(2), *_view_runtime_helpers(need_read=True, need_write=True),
        spx_portable_reference_runtime_v5_source(), '''
struct call_environment { uint32_t side; struct spx_mutable_world *world; spx_view_v5 buffer; };
struct call_machine { struct call_environment *environment; uint32_t entry;''',
        *(f'  uint32_t word_{i};' for i in range(len(words))), '};', '''
static uint32_t counts[2], before_id, probe;
static uint8_t before_byte;
static spx_view_v5 shared_transition(void *opaque, uint32_t id) {
  struct call_environment *env=opaque;
  __CPROVER_assert(counts[env->side]++==0U,"caller-dependency-call-capacity");
  __CPROVER_assume(counts[env->side]==1U);
  if (!env->side) { before_id=id; before_byte=spx_mutable_byte(env->world,probe); }
  else {
    __CPROVER_assert(id==before_id,"caller-dependency-arguments");''',
        f'    if ({readable}) __CPROVER_assert(spx_mutable_byte(env->world,probe)==before_byte,"caller-dependency-current-input-memory");',
        '  }', f'  spx_mutable_event(env->world,UINT32_C({address}),UINT32_C({extent}),0U,1U,0U);',
        '  return env->buffer;', '}', '''
static uint32_t machine_read(void *opaque,uint32_t address,uint32_t width,uint32_t *fault) {
  struct call_machine *machine=opaque;
  __CPROVER_assert(width==4U,"caller-access-width"); *fault=0U;''']
    source += [f'  if(address=={position(row["offset"])}) return machine->word_{i};' for i, row in enumerate(words)]
    source += ['  __CPROVER_assert(0,"caller-private-read-frame"); *fault=1U; return 0U;', '}', '''
static void machine_write(void *opaque,uint32_t address,uint32_t width,uint32_t value,uint32_t *fault) {
  struct call_machine *machine=opaque;
  __CPROVER_assert(width==4U,"caller-access-width"); *fault=0U;''']
    source += [f'  if(address=={position(row["offset"])}) {{machine->word_{i}=value; return;}}'
               for i, row in enumerate(words) if row['writable']]
    source += ['  __CPROVER_assert(0,"caller-private-write-frame"); *fault=1U;', '}', '''
spx_call_status spx_invoke_call(spx_runtime *runtime,const spx_call_event *event,
    const spx_machine_state *input,spx_machine_state *output) {
  struct call_machine *machine=runtime->context;
  __CPROVER_assert(event->kind==SPX_CALL_INTERNAL_DIRECT && event->call_index==0U &&
      event->arguments==0 && event->argument_count==0U && event->stack_input_count==1U &&
      event->stack_inputs!=0,"caller-dependency-event");''',
        f'  __CPROVER_assert(event->source_rva=={d["entry"]}U && event->instruction_rva=={d["instruction"]}U &&',
        f'      event->target_rva=={d["callee"]}U && event->return_rva=={d["successor"]}U,"caller-dependency-edge");',
        '  __CPROVER_assert(event->stack_inputs[0].offset==0U && event->stack_inputs[0].width==4U,"caller-dependency-capture");',
        f'  __CPROVER_assert(input->esp=={position(d["stack_delta"])},"caller-dependency-stack");', '''
  uint32_t fault=0U;
  uint32_t id=machine_read(machine,input->esp,4U,&fault);
  __CPROVER_assert(!fault && id==event->stack_inputs[0].value,"caller-dependency-stack-value");
  (void)shared_transition(machine->environment,id);
  *output=*input;''', f'  output->eax=UINT32_C({address});']
    source += [f'  {{uint32_t arbitrary; output->{field}=arbitrary;}}' for field in d['clobbers']]
    source += ['  return SPX_CALL_OK;', '}']
    projection = d['source']
    context_type = projection['context_type']
    services_type = context_type.removesuffix('_context_v5') + '_services_v5'
    service = projection['service_id']
    source += [f'static spx_view_v5 authored_region({context_type} *context) {{',
        f'  spx_view_v5 value=context->services->{service}(context->services->context,{projection["arguments"][0]}U);',
        '  return value;', '}', f'void {ENTRY}(void) {{',
        '  uint32_t arbitrary_probe; probe=arbitrary_probe;']
    reference = ','.join(f'UINT64_C({d["result_reference"][key]})' for key in ('domain','object','generation','offset','extent'))
    # Separate named worlds avoid SMT array-of-struct update expansion. These
    # are fixed proof sides, not unrolling of source application control flow.
    for i, side in enumerate(('left', 'right')):
        source += [f'  struct spx_mutable_world world_{side}={{0}};',
            f'  struct spx_mutable_domain domain_{side}={{&world_{side},{address}U,{extent}U,3U}};',
            f'  spx_runtime view_runtime_{side}={{.context=&domain_{side},.read=spx_mutable_read,.write=spx_mutable_write}};',
            f'  spx_component_view_context transport_{side}={{&view_runtime_{side},{address}U,{extent}U,3U}};',
            f'  struct call_environment env_{side}={{.side={i}U,.world=&world_{side},.buffer={{',
            f'    .base={{{reference},3U}},.extent={extent}U,.element_width=1U,',
            f'    .context=&transport_{side},.access_context=&transport_{side},',
            '    .read_u8=spx_component_view_read,.write_u8=spx_component_view_write,',
            '    .read=spx_component_view_read_span,.write=spx_component_view_write_span}};']
    source += ['  spx_view_v5 saved=env_right.buffer;', '  spx_machine_state initial,state;',
        f'  __CPROVER_assume((int64_t)initial.esp+INT64_C({d["low"]})>=0 && (int64_t)initial.esp+INT64_C({d["high"]})<=INT64_C(4294967296));',
        f'  __CPROVER_assume((int64_t)initial.esp+{d["high"]}<=INT64_C({d["image_base"]}) || (int64_t)initial.esp+INT64_C({d["low"]})>=INT64_C({d["image_base"]+d["image_size"]}));',
        '  struct call_machine machine; __CPROVER_havoc_object(&machine);',
        '  machine.environment=&env_left; machine.entry=initial.esp;',
        *(f'  uint32_t saved_word_{i}=machine.word_{i};' for i, row in enumerate(words) if row['exit']['kind']=='preserved'),
        f'  spx_runtime runtime={{.context=&machine,.read=machine_read,.write=machine_write,.image_base={d["image_base"]}U}};',
        '  state=initial;', f'  spx_step_result step=spx_sub_{d["entry"]:08x}(&runtime,&state,{d["entry"]}U);',
        f'  __CPROVER_assert(step.kind==SPX_FALLTHROUGH && step.target_rva=={d["successor"]}U,"caller-successor");',
        f'  __CPROVER_assert((int64_t)state.esp==(int64_t)initial.esp+INT64_C({d["stack_delta"]}) && state.eax=={address}U,"caller-register-transport");']
    for i, row in enumerate(words):
        expected = f'saved_word_{i}' if row['exit']['kind']=='preserved' else f'{row["exit"]["value"]}U'
        source.append(f'  __CPROVER_assert(machine.word_{i}=={expected},"caller-word-{i}-transport");')
    frame = frame_equalities(_architectural_state_equalities('state','initial'), [*d['clobbers'],'eax','esp'])
    source += ['  uint32_t continuation_slot,continuation_byte; __CPROVER_assume(continuation_slot<8U && continuation_byte<10U);',
        '  __CPROVER_assert('+' && '.join(frame)+',"caller-register-frame");',
        f'  {services_type} services={{.context=&env_right,.{service}=shared_transition}};',
        f'  {context_type} context={{.services=&services}};', '  spx_view_v5 result=authored_region(&context);']
    fields = ['base.'+key for key in ('domain','object','generation','offset','extent','permissions')]
    fields += ['extent','element_width','context','access_context','read_u8','write_u8','read','write']
    source += ['  __CPROVER_assert('+' && '.join(f'result.{key}==saved.{key}' for key in fields)+',"caller-live-view-transport");',
        '  __CPROVER_assert(counts[0]==1U && counts[1]==1U,"caller-call-count");',
        '  __CPROVER_assert(spx_mutable_byte(&world_left,probe)==spx_mutable_byte(&world_right,probe),"caller-post-memory");',
        f'  uint32_t offset; uint8_t byte; __CPROVER_assume(offset<{extent}U);',
        f'  __CPROVER_assert(spx_view_read_u8(&saved,offset,&byte)==0U && byte==spx_mutable_byte(&world_right,{address}U+offset),"caller-old-alias-current-memory");', '}']
    return '\n'.join(source)+'\n'
