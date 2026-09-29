"""Conditional terminal services for the existing live-object product models.

An explicit runtime premise is required; a void signature does not imply exit.
For source dependence, a terminating first invocation runs the second from its
checker callback. The second either terminates at the same service and memory,
or fails outcome correspondence. There are at most two authored invocations;
neither continues beyond its terminal service. Frame checks use one invocation.
No setjmp, source rewriting, or production continuation API is introduced.
"""
from .component_c_v5 import _parameter_type, _result_type
from .machine_overlay_services_v5 import _c_identifier


def checked_terminal_services(bundle, rows):
    if not isinstance(rows, (list, tuple)):
        raise ValueError('object terminal services must be an explicit list')
    services = {v.identity: v for v in bundle.interface.services}
    result = []
    for row in rows:
        fields = {'service_id', 'id', 'revision', 'status', 'disposition', 'requires', 'ensures', 'unverified'}
        if (not isinstance(row, dict) or set(row) != fields
                or any(not isinstance(row[k], str) or not row[k] for k in ('service_id', 'id', 'requires', 'ensures'))
                or row['service_id'] not in services or row['status'] != 'unverified'
                or type(row['revision']) is not int or row['revision'] <= 0 or row['disposition'] != 'terminates'
                or not isinstance(row['unverified'], list) or not row['unverified']
                or any(not isinstance(v, str) or not v for v in row['unverified'])):
            raise ValueError('object terminal service needs an explicit unverified termination premise')
        service = services[row['service_id']]
        signature = bundle.intent.schema.signature_index[service.signature_id]
        if signature.parameters or signature.results or service.effect_ids:
            raise ValueError('object terminal service currently requires a zero-argument void boundary')
        result.append(dict(row))
    ids = [r['service_id'] for r in result]
    if ids != sorted(set(ids)) or set(ids) != set(services):
        raise ValueError('object terminal service coverage differs')
    if result:
        operations = bundle.intent.operations
        if (len(operations) != 1 or set(operations[0]['allowed_service_ids']) != set(ids)
                or operations[0]['lifecycle_bindings'] or operations[0]['checked_interaction_contract_ids']):
            raise ValueError('object terminal operation requires its complete explicit service boundary')
    return result


def terminal_model_runtime(*, bundle, signature, symbol, kind, services):
    """Generate checked stopping callbacks and the second source invocation."""
    component = _c_identifier(bundle.interface.identity)
    context = f'spx_{component}_context_v5'
    result_type = _result_type(bundle.intent.schema.type_index, signature)
    fields = [f'{_parameter_type(bundle.intent.schema.type_index, v)} parameter_{i};'
              for i, v in enumerate(signature.parameters)]
    if result_type != 'void':
        fields.append(f'{result_type} result_right;')
    lines = ['static struct { uint32_t left_service; void *opaque_left,*opaque_right;',
        ' struct spx_mutable_world *world_left,*world_right;', f' {context} *context_right;',
        *fields, '} spx_object_terminal;', 'static void spx_object_terminal_run_right(void);']
    for i, row in enumerate(services):
        for side in ('left', 'right'):
            lines += [f'static void spx_object_terminal_{side}_{i}(void *opaque){{',
                f' __CPROVER_assert(opaque==spx_object_terminal.opaque_{side},"spx-object-terminal-context");']
            if kind != 'frame':
                if side == 'left':
                    lines += [f' spx_object_terminal.left_service={i+1}U;', ' spx_object_terminal_run_right();',
                        ' __CPROVER_assert(0,"spx-object-terminal-right-returned");']
                else:
                    lines += [f' __CPROVER_assert(spx_object_terminal.left_service=={i+1}U,"spx-object-terminal-outcome");',
                        ' __CPROVER_assert(spx_object_terminal.world_left->observed_byte==',
                        '  spx_object_terminal.world_right->observed_byte,',
                        '  "spx-object-terminal-current-memory");']
            lines += [' __CPROVER_assume(0);', '}']
    if kind != 'frame':
        args = ['spx_object_terminal.context_right',
                *(f'spx_object_terminal.parameter_{i}' for i in range(len(signature.parameters)))]
        prefix = 'spx_object_terminal.result_right=' if result_type != 'void' else ''
        lines += ['static void spx_object_terminal_run_right(void){',
            ' spx_mutable_frame=spx_object_terminal.world_right;', f' {prefix}{symbol}({",".join(args)});',
            ' __CPROVER_assert(spx_object_terminal.left_service==0U,"spx-object-normal-outcome");', '}']
    return lines


def terminal_model_setup(*, bundle, signature, views, sides, services):
    component = _c_identifier(bundle.interface.identity)
    lines = ['  spx_object_terminal.left_service=0U;']
    for side in sides:
        callbacks = ','.join(f'.{_c_identifier(row["service_id"])}=spx_object_terminal_{side}_{i}'
                             for i, row in enumerate(services))
        lines += [f'  spx_{component}_services_v5 services_{side}={{.context=&env_{side},{callbacks}}};',
            f'  context_{side}.services=&services_{side};',
            f'  spx_object_terminal.opaque_{side}=&env_{side};',
            f'  spx_object_terminal.world_{side}=&world_{side};']
    if 'right' in sides:
        lines.append('  spx_object_terminal.context_right=&context_right;')
        for i, value in enumerate(signature.parameters):
            index = next((j for j, (root, item) in enumerate(views)
                          if root == 'parameter' and item.identity == value.identity), None)
            argument = f'&view_{index}_right' if index is not None else f'parameter_{i}'
            lines.append(f'  spx_object_terminal.parameter_{i}={argument};')
    return lines


def terminal_machine_dispatch(services, bindings):
    """Exact event correspondence; the original must propagate terminal control."""
    from .bisimulation_native_calls import _event
    if not isinstance(bindings, list) or len(bindings) != len(services):
        raise ValueError('object terminal machine binding coverage differs')
    lines = ['spx_call_status spx_invoke_call(spx_runtime *rt,const spx_call_event *event,',
        ' const spx_machine_state *input,spx_machine_state *output){',
        ' struct spx_object_machine *m=rt->context;*output=*input;',
        ' __CPROVER_assert(m->env->terminal==0U,"spx-object-terminal-single-call");']
    for i, (service, row) in enumerate(zip(services, bindings, strict=True)):
        if not isinstance(row, dict) or set(row) != {'service_id', 'event'} or row['service_id'] != service['service_id']:
            raise ValueError('object terminal machine service differs')
        event = _event(row['event'])
        if event['kind'] != 'import' or event['argument_count'] or event['stack_input_count']:
            raise ValueError('object terminal machine rule requires a zero-argument import event')
        checks = ['event->kind==SPX_CALL_EXTERNAL_IMPORT', 'event->ordinal==0U']
        checks += [f'event->{k}==UINT32_C({v})' for k, v in sorted(event.items()) if type(v) is int]
        for key in ('dll', 'symbol'):
            # Do not add a libc string implementation to the proof model.
            checks.append(f'event->{key}!=0')
            checks += [f'event->{key}[{j}]=={ord(c)}' for j, c in enumerate(event[key])]
            checks.append(f'event->{key}[{len(event[key])}]==0')
        lines += [f' if({" && ".join(checks)}){{m->env->terminal={i+1}U;return SPX_CALL_NONLOCAL;}}']
    lines += [' __CPROVER_assert(0,"spx-object-machine-unmodeled-call");return SPX_CALL_UNIMPLEMENTED;', '}']
    return lines
