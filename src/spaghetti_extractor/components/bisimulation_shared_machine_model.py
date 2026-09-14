"""Compact original/source comparison for borrowed fixed-image service leaves.

This conditional renderer is consumed by the public diagnostic checker, not by
the provider qualification reader.
It executes retained Behavioral-C with explicit private-stack, image-byte and
stdcall service boundaries, sharing the existing sparse source/service model.
Native origin admission and runtime compatibility remain separate obligations.
"""

from spaghetti_extractor.components.bisimulation_shared_model import _render_shared_source_model, _matching_state
from spaghetti_extractor.components.bisimulation_shared_services import normalize_shared_service_bindings
from spaghetti_extractor.components.bisimulation_shared_summary import shared_summary_operation
from spaghetti_extractor.components.bisimulation_private_frame import parse_stack_writes
from spaghetti_extractor.components.bisimulation_clobber_frame import parse_clobbers, frame_equalities
from spaghetti_extractor.components.bisimulation_harness import _architectural_state_equalities
from spaghetti_extractor.components.binding_intent import ComponentMachineBindingIntentV1
from spaghetti_extractor.components.machine_overlay_state_views import checked_state_view, checked_state_view_result
from spaghetti_extractor.components.machine_overlay_services_v5 import _c_identifier
from spaghetti_extractor.components.capabilities import spx_portable_reference_runtime_v5_source


def shared_machine_runtime_contract():
    """Name the experimental trust boundary; do not register it as qualified."""
    return {
        'id': 'borrowed-image-shared-machine-domain', 'revision': 1,
        'inputs': 'Related current image bytes; fixed borrowed image views; arbitrary admitted private stack and machine registers.',
        'memory': 'Little-endian one-to-four-byte accesses; successful valid accesses; writes confined to writable image views or declared private ranges.',
        'private': 'Private ranges are disjoint from the whole image; entry stack words bind the return target and scalar parameters; other private bytes are arbitrary.',
        'services': 'Only bound direct named stdcall imports; related scalar arguments, view addresses, current input bytes, ordered calls, selected result domains and writable ranges.',
        'service_frame': 'Preserve nonvolatile general registers and x87/segment state; arbitrary ECX, EDX and integer flags; pop the bound argument bytes.',
        'lifetime': 'Borrowed image views remain live throughout the call; no allocation, release, callback, nonlocal exit or origin rebinding.',
        'outcomes': 'Check normal return target, stack adjustment, raw result alias and undeclared register clobbers; reject other original control outcomes.',
        'progress': 'All selected language-safety and unwinding assertions must pass; resource bounds never restrict admitted inputs.',
    }


def _string_equal(expression, value):
    return ' && '.join([f'{expression} != 0', *(
        f'{expression}[{i}] == {ord(char)}' for i, char in enumerate(value+'\0'))])


def render_shared_machine_model(*, bundle, operation_id, symbol, shared_contract,
                                binding_intent, service_bindings, machine_domain):
    """Compare the complete original leaf against ordinary C under stated inputs.

    The caller must bind and compile the actual transfer bodies separately. No
    declaration here establishes their identity or authorizes a replacement.
    Every original memory access, service site and normal return is checked.
    Unwinding assertions remain required: capacity is not an input assumption.
    """
    binding = ComponentMachineBindingIntentV1.parse(binding_intent)
    if binding.component_id != bundle.interface.identity:
        raise ValueError('shared machine binding names another component')
    operation = next(row.semantics for row in binding.operations if row.semantics.operation_id == operation_id)
    logical = next(row for row in bundle.interface.operations if row.identity == operation_id)
    signature = bundle.intent.schema.signature_index[logical.signature_id]
    if (len(operation.entry_rvas) != 1 or any(value.type_id not in bundle.intent.schema.type_index
            or bundle.intent.schema.type_index[value.type_id].kind != 'integer'
            or bundle.intent.schema.type_index[value.type_id].body != {'signed': False, 'width_bits': 32}
            for value in signature.parameters)):
        raise ValueError('shared machine comparison requires one entry and unsigned word parameters')
    selected = normalize_shared_service_bindings(bundle, service_bindings)
    if selected != shared_contract.get('service_contracts'):
        raise ValueError('shared machine service contracts differ from the source premises')
    alias, services = shared_summary_operation(bundle, operation_id, shared_contract)
    projection = operation.machine_projection['operation']
    projections = {row['id']: row for row in projection['state']}
    views = {item.value.identity: checked_state_view(bundle, item, projections[item.value.identity])[1:]
             for item in bundle.interface.state}
    result_projection = next(row['projection'] for row in projection['results'] if row['id'] == signature.results[0].identity)
    result_state, _, _ = checked_state_view_result(bundle=bundle, value=signature.results[0],
        projection=result_projection, state_projections=projections)
    if result_state.value.identity != alias:
        raise ValueError('shared machine result alias differs from the authored postcondition')
    if set(machine_domain) != {'image_base', 'image_size', 'private_accesses', 'private_writes', 'clobbers'}:
        raise ValueError('shared machine domain fields differ')
    accesses = parse_stack_writes(machine_domain['private_accesses'])
    writes = parse_stack_writes(machine_domain['private_writes'])
    clobbers = parse_clobbers(machine_domain['clobbers'])
    low = min((offset for offset, _ in accesses), default=0)
    high = max((offset+size for offset, size in accesses), default=0)
    base, size = machine_domain['image_base'], machine_domain['image_size']
    if (type(base) is not int or type(size) is not int or not 0 < base < base+size <= 2**32
            or not low <= 0 < 4 <= high or high-low > 256
            or not (high-low <= base or base+size+high-low <= 2**32)
            or any(not base <= address < address+extent <= base+size for extent, _, address in views.values())
            or any(not any(a <= offset and offset+count <= a+n for a,n in accesses) for offset,count in writes)
            or any(offset+count > 0 for offset,count in writes) or 'eax' in clobbers):
        raise ValueError('shared machine image/private frame is unsupported')
    parameters = {row['id']: row['projection'] for row in projection['parameters']}
    occupied = set(range(4))  # Return address and logical inputs must coexist.
    for value in signature.parameters:
        p = parameters[value.identity]
        if (set(p) != {'kind','at','offset','width'} or p['kind'] != 'stack' or p['at'] != 'entry'
                or p['width'] != 32 or type(p['offset']) is not int or p['offset'] < 4
                or not any(a <= p['offset'] and p['offset']+4 <= a+n for a,n in accesses)
                or occupied.intersection(range(p['offset'],p['offset']+4))):
            raise ValueError('shared machine parameter lacks a full admitted stack word')
        occupied.update(range(p['offset'],p['offset']+4))
    component = _c_identifier(bundle.interface.identity)
    context_type = f'spx_{component}_context_v5'
    def ranges(rows):
        return '('+' || '.join(f'((int64_t)address >= (int64_t)machine->entry + INT64_C({offset}) && '
            f'(int64_t)address + width <= (int64_t)machine->entry + INT64_C({offset+n}))' for offset,n in rows)+')' if rows else '0U'
    source = ['#include "behavioral-c.h"', spx_portable_reference_runtime_v5_source(),
        f'struct spx_shared_machine {{ {context_type} *owner; struct spx_mutable_world *world;',
        f'  uint32_t entry; uint8_t stack[{high-low}]; }};',
        'static uint32_t spx_shared_machine_read(void *opaque, uint32_t address, uint32_t width, uint32_t *fault) {',
        '  struct spx_shared_machine *machine = opaque;',
        '  __CPROVER_assert(width >= 1U && width <= 4U, "spx-shared-machine-access-width");',
        f'  if ({ranges(accesses)}) {{',
        '    uint32_t value = 0U;',
        f'    for (uint32_t i=0; i<width; ++i) value |= (uint32_t)machine->stack[address-machine->entry+{-low}U+i] << (8U*i);',
        '    *fault=0U; return value;', '  }']
    for name, (extent, _, address) in views.items():
        source += [f'  if (address >= UINT32_C({address}) && (uint64_t)address+width <= UINT64_C({address+extent})) {{',
            '    uint32_t value=0U;',
            '    for (uint32_t i=0; i<width; ++i) value |= (uint32_t)spx_mutable_byte(machine->world,address+i) << (8U*i);',
            '    *fault=0U; return value;', '  }']
    source += ['  __CPROVER_assert(0, "spx-shared-machine-readable-frame"); *fault=1U; return 0U;', '}',
        'static void spx_shared_machine_write(void *opaque, uint32_t address, uint32_t width, uint32_t value, uint32_t *fault) {',
        '  struct spx_shared_machine *machine = opaque;',
        '  __CPROVER_assert(width >= 1U && width <= 4U, "spx-shared-machine-access-width");',
        f'  if ({ranges(writes)}) {{',
        f'    for (uint32_t i=0; i<width; ++i) machine->stack[address-machine->entry+{-low}U+i] = (uint8_t)(value >> (8U*i));',
        '    *fault=0U; return;', '  }']
    for name, (extent, permissions, address) in views.items():
        if permissions & 2:
            source += [f'  if (address >= UINT32_C({address}) && (uint64_t)address+width <= UINT64_C({address+extent})) {{',
                '    spx_mutable_event(machine->world,address,width,value,0U,0U); *fault=0U; return;', '  }']
    source += ['  __CPROVER_assert(0, "spx-shared-machine-writable-frame"); *fault=1U;', '}',
        'spx_call_status spx_invoke_call(spx_runtime *rt, const spx_call_event *event,',
        '    const spx_machine_state *input, spx_machine_state *output) {',
        '  struct spx_shared_machine *machine = rt->context;',
        '  uint32_t fault=0U; *output=*input;']
    sites = set()
    for service in service_bindings:
        if service.get('abi_template') != 'pe32-stdcall-v1' or service.get('ordinal') is not None:
            raise ValueError('shared machine services require direct named stdcall imports')
        sig = services[service['service_id']][0]
        if not isinstance(service.get('events'), list) or not service['events']:
            raise ValueError('shared machine service events are absent')
        for event in service['events']:
            if (not isinstance(event, dict) or set(event) != {'unit_id','source_rva','event_index',
                    'instruction_rva','return_rva','event_stack_offsets'}
                    or event['unit_id'] not in operation.unit_ids or event['event_stack_offsets'] != []
                    or any(type(event[key]) is not int or not 0 <= event[key] < 2**32
                           for key in ('source_rva','event_index','instruction_rva','return_rva'))):
                raise ValueError('shared machine service event metadata is unsupported')
            site = event['instruction_rva']
            if site in sites:
                raise ValueError('shared machine service sites are duplicated')
            sites.add(site)
            source += [f'  if (event->instruction_rva == UINT32_C({site})) {{',
                f'    __CPROVER_assert(event->kind == SPX_CALL_EXTERNAL_IMPORT && event->source_rva == UINT32_C({event["source_rva"]}) &&',
                f'        event->return_rva == UINT32_C({event["return_rva"]}) && event->call_index == {event["event_index"]}U &&',
                '        event->target_rva == 0U && event->arguments == 0 && event->argument_count == 0U &&',
                '        event->stack_inputs == 0 && event->stack_input_count == 0U && event->ordinal == 0U &&',
                f'        !event->has_ordinal && {_string_equal("event->dll", service["dll"])} &&',
                f'        {_string_equal("event->symbol",service["import_symbol"])}, "spx-shared-machine-service-identity");']
            args=[]
            for i,value in enumerate(sig.parameters):
                source += [f'    uint32_t arg{i}=spx_shared_machine_read(machine,input->esp+{service["argument_offsets"][i]}U,4U,&fault);',
                    '    __CPROVER_assert(fault==0U, "spx-shared-machine-service-input");']
                if value.interpretation == 'view':
                    state = _matching_state(bundle,value)[0].identity
                    source += [f'    __CPROVER_assert(arg{i} == UINT32_C({views[state][2]}), "spx-shared-machine-service-view");']
                    args.append(f'&machine->owner->state.{_c_identifier(state)}')
                else:
                    args.append(f'arg{i}')
            source += [f'    output->eax = machine->owner->services->{_c_identifier(service["service_id"])}(',
                f'        machine->owner->services->context, {", ".join(args)});',
                f'    output->esp=input->esp+{4*len(sig.parameters)}U;']
            for field in ('ecx','edx','cf','zf','sf','of','pf','df','eflags'):
                source += [f'    uint32_t arbitrary_{field}; output->{field}=arbitrary_{field};']
            source += ['    return SPX_CALL_OK;', '  }']
    source += ['  __CPROVER_assert(0, "spx-shared-machine-unmodeled-call"); return SPX_CALL_UNIMPLEMENTED;', '}',
        f'static spx_view_v5 spx_shared_original({context_type} *context'+
            ''.join(f', uint32_t {_c_identifier(value.identity)}' for value in signature.parameters)+') {',
        '  struct spx_shared_environment *env=context->services->context;',
        '  spx_machine_state initial, state; uint32_t return_target;',
        f'  __CPROVER_assume(initial.esp >= {-low}U && (uint64_t)initial.esp+{high}U <= UINT64_C(4294967296));',
        f'  __CPROVER_assume((uint64_t)initial.esp+{high}U <= UINT64_C({base}) || (uint64_t)initial.esp >= UINT64_C({base+size-low}));',
        '  struct spx_shared_machine machine;',
        # Arbitrary private contents, followed only by the actual entry inputs.
        '  __CPROVER_havoc_object(&machine);',
        '  machine.owner=context; machine.world=env->world; machine.entry=initial.esp;']
    for offset, expression in [(0,'return_target'), *[(parameters[v.identity]['offset'],_c_identifier(v.identity)) for v in signature.parameters]]:
        source += [f'  for (uint32_t i=0; i<4U; ++i) machine.stack[{offset-low}U+i]=(uint8_t)({expression} >> (8U*i));']
    source += ['  spx_runtime runtime={.context=&machine,.read=spx_shared_machine_read,.write=spx_shared_machine_write};',
        f'  runtime.image_base=UINT32_C({base}); state=initial;',
        f'  spx_step_result result=spx_sub_{operation.entry_rvas[0]:08x}(&runtime,&state,UINT32_C({operation.entry_rvas[0]}));',
        '  __CPROVER_assert(result.kind==SPX_RETURN && result.value==return_target && state.esp==initial.esp+4U,',
        '      "spx-shared-machine-normal-return");',
        f'  __CPROVER_assert(state.eax==UINT32_C({views[alias][2]}), "spx-shared-machine-result-alias");',
        '  uint32_t continuation_slot, continuation_byte;',
        '  __CPROVER_assume(continuation_slot<8U && continuation_byte<10U);']
    equalities = frame_equalities(_architectural_state_equalities('state','initial'), [*clobbers,'eax','esp'])
    source += ['  __CPROVER_assert('+' && '.join(equalities)+', "spx-shared-machine-register-frame");',
               f'  return context->state.{_c_identifier(alias)};', '}']
    adapter = {'source':'\n'.join(source), 'symbol':'spx_shared_original',
               'state_addresses':{name:row[2] for name,row in views.items()}}
    return _render_shared_source_model(bundle=bundle,operation_id=operation_id,symbol=symbol,
        kind='input_dependence',shared_contract=shared_contract,original_adapter=adapter)
