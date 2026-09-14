"""Local shared-view source models with paired ordered service observations.

This theorem is conditional on the modeled fixed-view service footprint. It is
not a provider summary: exact service binding and consumer composition remain
separate. No state initializer or terminated-string premise is introduced.
"""

from .bisimulation_mutable_memory import sparse_mutable_memory_runtime, MAX_MUTABLE_MODEL_BYTES
from .component_c_v5 import _parameter_type, _result_type
from .interface_package_v5 import ComponentInterfaceIntentV1, compile_component_interface_v5
from .machine_overlay_services_v5 import _c_identifier
from .machine_overlay_v5 import _view_runtime_helpers
from .normal_exit_postconditions import shared_result_postcondition
from .relation_v5 import ComponentRelationIntentV1
from .bisimulation_shared_services import shared_service_contract_index, shared_service_admission_lines
from . import bisimulation_source_dependencies as source_dependencies

SHARED_CONTRACT_POLICY = "fixed-shared-view-service-source-contract-v1"
SHARED_MODEL_POLICY = "fixed-shared-view-paired-service-trace-v1"
SHARED_DEPENDENCY_POLICY = "fixed-shared-view-service-source-dependencies-v1"
SHARED_DEPENDENCY_MODEL = "fixed-shared-view-paired-service-dependencies-v1"
_VIEW_FIELDS = ("base.domain", "base.object", "base.generation", "base.offset", "base.extent",
                "base.permissions", "extent", "element_width", "context", "read_u8", "write_u8",
                "access_context", "read", "write")


def shared_source_shape(bundle):
    """Recognize this local theorem domain; declarations alone grant no facts."""
    interface = bundle.interface
    types = bundle.intent.schema.type_index
    if not interface.state or not interface.services or len(bundle.intent.protocol_states) != 1:
        return None
    def scalar(value):
        return (value.interpretation == "value" and value.access == "none" and not value.nullable
                and types[value.type_id].kind in {"integer", "bool", "enum"})
    def view(value):
        return (value.interpretation == "view" and not value.nullable and value.access in {"read", "read_write"}
                and value.extent.get("kind") == "fixed" and isinstance(value.extent.get("bytes"), int)
                and not isinstance(value.extent["bytes"], bool) and 0 < value.extent["bytes"] <= MAX_MUTABLE_MODEL_BYTES
                and types[value.type_id].kind == "pointer"
                and types[types[value.type_id].body["pointee_type_id"]].kind == "integer"
                and types[types[value.type_id].body["pointee_type_id"]].body["width_bits"] == 8)
    if any(item.initial is not None or not view(item.value) for item in interface.state):
        return None
    if sum(item.value.extent['bytes'] for item in interface.state) > MAX_MUTABLE_MODEL_BYTES:
        return None
    for op in interface.operations:
        signature = bundle.intent.schema.signature_index[op.signature_id]
        if (not all(scalar(v) for v in signature.parameters) or len(signature.results) != 1
                or not view(signature.results[0])):
            return None
    for service in interface.services:
        signature = bundle.intent.schema.signature_index[service.signature_id]
        if len(signature.results) != 1 or not scalar(signature.results[0]):
            return None
        for value in signature.parameters:
            if scalar(value):
                continue
            if not view(value) or len(_matching_state(bundle, value)) != 1:
                return None
    return tuple(sorted(op.identity for op in interface.operations)) or None


def _matching_state(bundle, value):
    return [item.value for item in bundle.interface.state if item.value.type_id == value.type_id
            and item.value.extent == value.extent and item.value.access == value.access]


def _equal(left, right):
    return ' && '.join(f'{left}.{field} == {right}.{field}' for field in _VIEW_FIELDS)


def _current_zero_witness(capacity):
    """A sufficient witness search over stores, never over the buffer extent.

    Event history only locates candidates. Reading current memory rejects a
    later overwrite through any alias. Arbitrary input/service bytes alone do
    not establish a zero. This conservative local proof method does not define
    the predicate as historical and must not restrict a body-free summary to
    this source's store history.
    """
    return f'''
static uint32_t spx_shared_current_zero(const struct spx_mutable_world *world,
    uint32_t address, uint64_t extent) {{
  uint32_t found = 0U;
  for (uint32_t j=0U; j<{capacity}U; ++j) {{
    if (j < world->count && !world->events[j].service) {{
      const struct spx_mutable_event *event = &world->events[j];
      for (uint32_t k=0U; k<4U; ++k) {{
        uint64_t candidate = (uint64_t)event->address + k;
        if (k < event->extent && candidate < UINT64_C(4294967296) &&
            candidate >= address && candidate < (uint64_t)address + extent &&
            spx_mutable_byte(world, (uint32_t)candidate) == 0U)
          found = 1U;
      }}
    }}
  }}
  return found;
}}
'''.strip().splitlines()


def render_shared_source_model(*, bundle, operation_id, symbol, kind, shared_contract, summary_dependencies=()):
    return _render_shared_source_model(bundle=bundle, operation_id=operation_id, symbol=symbol,
        kind=kind, shared_contract=shared_contract, summary_dependencies=summary_dependencies)


def _render_shared_source_model(*, bundle, operation_id, symbol, kind, shared_contract,
                                summary_dependencies=(), original_adapter=None):
    """Share storage/service semantics with the separate original-behavior experiment.

    The ordinary source certificate renderer never supplies an original adapter.
    That experiment has a different theorem and cannot validate as source-only
    evidence merely by retaining this implementation's model or entry names.
    """
    bundle = compile_component_interface_v5(ComponentInterfaceIntentV1.parse(bundle.intent.to_payload()))
    if (shared_source_shape(bundle) is None or kind not in {'frame', 'input_dependence'}
            or symbol != _c_identifier(symbol)
            or set(shared_contract) not in ({'relation_intent', 'maximum_calls', 'maximum_memory_events'},
                {'relation_intent', 'maximum_calls', 'maximum_memory_events', 'service_contracts'})):
        raise ValueError('shared source model inputs or domain are unsupported')
    if summary_dependencies:
        source_dependencies.validate_dependencies(summary_dependencies, component_id=bundle.interface.identity)
    selected_contracts = (None if 'service_contracts' not in shared_contract else
                          shared_service_contract_index(bundle,shared_contract['service_contracts']))
    limit = shared_contract['maximum_calls']
    if not isinstance(limit, int) or isinstance(limit, bool) or not 0 < limit <= 64:
        raise ValueError('shared source service capacity is invalid')
    intent = ComponentRelationIntentV1.parse(shared_contract['relation_intent'])
    operations = {op.identity: op for op in bundle.interface.operations}
    if (intent.component_id != bundle.interface.identity or intent.status != 'ready_for_check'
            or {op['operation_id'] for op in intent.operations} != set(operations) or operation_id not in operations):
        raise ValueError('shared source relation operations differ from the interface')
    requirements = next(op['requirements'] for op in intent.operations if op['operation_id'] == operation_id)
    if len(requirements) != 1 or requirements[0]['relation'] != 'normal_exit_postcondition':
        raise ValueError('shared source model requires one authored result-to-state view equality')
    _, alias, has_zero = shared_result_postcondition(requirements[0]['expression'], bundle=bundle, operation_id=operation_id)
    types = bundle.intent.schema.type_index
    component = _c_identifier(bundle.interface.identity)
    signature = bundle.intent.schema.signature_index[operations[operation_id].signature_id]
    state = [item.value for item in bundle.interface.state]
    event_capacity = shared_contract['maximum_memory_events']
    service_signatures = [bundle.intent.schema.signature_index[s.signature_id] for s in bundle.interface.services]
    scalar_count = max(sum(v.interpretation == 'value' for v in s.parameters) for s in service_signatures)
    entry = f'spx_shared_{kind}_{_c_identifier(operation_id)}'
    context_type = f'spx_{component}_context_v5'
    lines = ['#include "state-machine-runtime.h"', '#include "portable-component-implementation.h"',
        *sparse_mutable_memory_runtime(event_capacity), *_view_runtime_helpers(need_read=True, need_write=True),
        f'static struct {{ uint32_t count[2], kind[{limit}]; uint64_t arguments[{limit}][{max(1, scalar_count)}], result[{limit}];',
        f'  uint8_t before[{limit}]; }} spx_shared_trace;',
        'static uint32_t spx_shared_probe;',
        f'struct spx_shared_environment {{ uint32_t side; struct spx_mutable_world *world; {context_type} *owner; }};',
        'uint8_t __CPROVER_uninterpreted_service_byte(uint32_t, uint32_t);']
    lines += source_dependencies.render_dependencies(summary_dependencies, mutable=True)
    if has_zero:
        lines += _current_zero_witness(event_capacity)
    for ordinal, (service, service_sig) in enumerate(zip(bundle.interface.services, service_signatures)):
        name = _c_identifier(service.identity)
        params = ['void *opaque'] + [f'{_parameter_type(types,v)} p_{_c_identifier(v.identity)}' for v in service_sig.parameters]
        result_type = _result_type(types, service_sig)
        lines += [f'static {result_type} spx_shared_service_{name}({", ".join(params)}) {{',
            '  struct spx_shared_environment *env = opaque;',
            '  uint32_t side = env->side, position = spx_shared_trace.count[side]++;',
            f'  __CPROVER_assert(position < {limit}U, "spx-shared-service-capacity");',
            f'  __CPROVER_assume(position < {limit}U);',
            f'  if (!side) spx_shared_trace.kind[position] = {ordinal}U;',
            f'  else __CPROVER_assert(spx_shared_trace.kind[position] == {ordinal}U, "spx-shared-service-order");']
        scalar_slot = 0
        writable = []
        for value in service_sig.parameters:
            arg = 'p_' + _c_identifier(value.identity)
            if value.interpretation == 'value':
                lines += [f'  if (!side) spx_shared_trace.arguments[position][{scalar_slot}] = (uint64_t){arg};',
                    f'  else __CPROVER_assert(spx_shared_trace.arguments[position][{scalar_slot}] == (uint64_t){arg}, "spx-shared-service-arguments");']
                scalar_slot += 1
            else:
                selected = _matching_state(bundle,value)[0]
                owner = 'env->owner->state.' + _c_identifier(selected.identity)
                lines += [f'  __CPROVER_assert({arg} != 0, "spx-shared-service-view-present");',
                    f'  __CPROVER_assume({arg} != 0);',
                    f'  __CPROVER_assert({_equal("(*"+arg+")", owner)}, "spx-shared-service-view-transport");']
                if value.access == 'read_write':
                    writable.append(owner)
        if selected_contracts is not None:
            lines += shared_service_admission_lines(service.identity,selected_contracts)
        lines += ['  if (!side) spx_shared_trace.before[position] = spx_mutable_byte(env->world,spx_shared_probe);',
            '  else __CPROVER_assert(spx_shared_trace.before[position] == spx_mutable_byte(env->world,spx_shared_probe), "spx-shared-service-input-memory");']
        for owner in writable:
            lines += [f'  {{ spx_component_view_context *view = {owner}.access_context;',
                '    spx_mutable_event(env->world,view->address,view->extent,0U,1U,position);', '  }']
        lines += [f'  if (!side) {{ {result_type} arbitrary; spx_shared_trace.result[position] = (uint64_t)arbitrary; }}',
        ]
        for footprint in (() if selected_contracts is None else selected_contracts[service.identity][2]):
            if 'written_count_capacity' not in footprint:
                continue
            capacity = 'p_' + _c_identifier(service_sig.parameters[footprint['written_count_capacity']].identity)
            view = 'p_' + _c_identifier(service_sig.parameters[footprint['base']].identity)
            lines += [
                f'  if (side) __CPROVER_assert(spx_shared_trace.result[position] < {capacity},',
                '      "spx-shared-selected-service-written-result");',
                f'  __CPROVER_assume(spx_shared_trace.result[position] < {capacity});',
                f'  {{ spx_component_view_context *view = {view}->access_context;',
                '    spx_mutable_event(env->world, view->address + (uint32_t)spx_shared_trace.result[position],',
                '        1U, 0U, 0U, 0U);',
                '  }']
        lines += [f'  return ({result_type})spx_shared_trace.result[position];', '}']
    parameters = [f'{context_type} *context'] + [f'{_parameter_type(types,v)} {_c_identifier(v.identity)}' for v in signature.parameters]
    if original_adapter is not None:
        if kind != 'input_dependence' or summary_dependencies:
            raise ValueError('original shared comparison requires a leaf paired memory model')
        lines += original_adapter['source'].splitlines()
    lines += [f'spx_view_v5 {symbol}({", ".join(parameters)})', '__CPROVER_requires(1)',
        '__CPROVER_ensures(1)', '__CPROVER_assigns(__CPROVER_object_whole(spx_mutable_frame), __CPROVER_object_whole(&spx_shared_trace));',
        f'void {entry}(void) {{', '  uint32_t arbitrary_probe; spx_shared_probe = arbitrary_probe;', '  spx_shared_trace.count[0] = 0U; spx_shared_trace.count[1] = 0U;']
    sides = ('left',) if kind == 'frame' else ('left','right')
    for value in signature.parameters:
        lines.append(f'  {_parameter_type(types,value)} {_c_identifier(value.identity)};')
    for side_no, side in enumerate(sides):
        lines += [f'  {context_type} context_{side};', f'  struct spx_mutable_world world_{side} = {{.count=0U}};',
            f'  struct spx_shared_environment env_{side} = {{{side_no}U,&world_{side},&context_{side}}};',
            f'  spx_{component}_services_v5 services_{side} = {{.context=&env_{side},' +
            ','.join(f'.{_c_identifier(s.identity)}=spx_shared_service_{_c_identifier(s.identity)}' for s in bundle.interface.services) + '};',
            f'  context_{side}.services = &services_{side}; context_{side}.protocol_state = 0;']
    for value in state:
        name, extent = _c_identifier(value.identity), value.extent['bytes']
        permissions = 3 if value.access == 'read_write' else 1
        address = '' if original_adapter is None else f" = UINT32_C({original_adapter['state_addresses'][value.identity]})"
        lines += [f'  uint32_t address_{name}{address}; spx_ref_v5 base_{name};',
            f'  __CPROVER_assume((uint64_t)address_{name} + {extent}U <= UINT64_C(4294967296));']
        for side in sides:
            prefix = f'{name}_{side}'
            lines += [f'  struct spx_mutable_domain domain_{prefix} = {{&world_{side},address_{name},{extent}U,{permissions}U}};',
                f'  spx_runtime runtime_{prefix} = {{.context=&domain_{prefix},.read=spx_mutable_read,.write=spx_mutable_write}};',
                f'  spx_component_view_context transport_{prefix} = {{&runtime_{prefix},address_{name},{extent}U,{permissions}U}};',
                f'  context_{side}.state.{name} = (spx_view_v5){{.base=base_{name},.extent={extent}U,.element_width=1U,',
                f'    .context=&transport_{prefix},.read_u8=spx_component_view_read,.access_context=&transport_{prefix},.read=spx_component_view_read_span,' +
                ('.write_u8=spx_component_view_write,.write=spx_component_view_write_span' if permissions == 3 else '.write_u8=0,.write=0') + '};']
    for side in sides:
        args = [f'&context_{side}'] + [_c_identifier(v.identity) for v in signature.parameters]
        if summary_dependencies:
            lines += [f'  spx_dependency_expected_context = &env_{side};']
        called = original_adapter['symbol'] if original_adapter is not None and side == 'left' else symbol
        lines += [f'  spx_mutable_frame = &world_{side};', f'  spx_view_v5 result_{side} = {called}({", ".join(args)});']
    # Keep mandatory top-level relational assertions first for the existing reader.
    condition = 'spx_shared_trace.count[0] == spx_shared_trace.count[1]' if kind == 'input_dependence' else '1'
    lines += [f'  __CPROVER_assert({condition}, "spx-shared-service-count");']
    if kind == 'input_dependence':
        lines += ['  __CPROVER_assert(spx_mutable_byte(&world_left,spx_shared_probe) == spx_mutable_byte(&world_right,spx_shared_probe), "spx-shared-post-memory");']
    for side in sides:
        lines += [f'  __CPROVER_assert({_equal("result_"+side,"context_"+side+".state."+_c_identifier(alias))}, "spx-shared-authored-result-alias");']
    if has_zero:
        extent = next(value.extent['bytes'] for value in state if value.identity == alias)
        for side in sides:
            lines += [f'  __CPROVER_assert(spx_shared_current_zero(&world_{side}, address_{_c_identifier(alias)}, {extent}U),',
                      '      "spx-shared-authored-current-zero");']
    lines += ['}']
    return '\n'.join(lines)+'\n', entry
