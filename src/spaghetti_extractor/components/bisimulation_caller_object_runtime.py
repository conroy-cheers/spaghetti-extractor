"""Render typed caller objects through the existing paired-call runtime.

Entry-relative addresses are evaluated once and retained as checker metadata.
At calls, native pointers come from checked private storage; source pointers come
from the actual live C views. No pointer reconstruction supplies object contents.
"""
from .bisimulation_caller_memory import U32
from .bisimulation_local_bytes import LocalBytesBinding
from .bisimulation_caller_local_records import LocalRecordBinding, local_record_definitions
from .relation_ir import RelationSortV1


def require(value, message):
    if not value: raise ValueError('caller object runtime: '+message)


def object_call_layout(definition, bundle, source_services, lower):
    from .bisimulation_caller_objects import local_view_definitions
    services = definition['services']
    active = any('objects' in row for row in services)
    if not active:
        require(not definition.get('local_views') and not definition.get('local_records'),
                'local storage needs a checked object call rule')
        return None
    require(all('objects' in row for row in services), 'every object-mode service needs its footprint')
    locals = local_view_definitions(definition, bundle.intent)
    record_locals = local_record_definitions(definition, bundle)
    capacity = max(1, *(len(row['objects']) for row in services))
    require(1 <= capacity <= 32, 'unsupported object capacity')
    declarations = ['struct spx_boundary_object {uint32_t address,permissions;uint64_t extent;};',
        f'static struct spx_boundary_object boundary_objects[{len(services)}][{capacity}];']
    initializers = []; bindings = {}; record_bindings = {}; call_time = False

    def initialize(row, target):
        address, extent = lower(row['address']), lower(row['extent'])
        permission = row['permissions']
        require(address.sort == U32 and extent.sort in {U32, RelationSortV1('bitvector', width=64)}
                and type(permission) is int and permission in {1, 2, 3}, 'invalid object span')
        initializers.extend([f'__CPROVER_assert({address.defined} && {extent.defined},"spx-caller-object-binding-defined");',
            f'{target}=(struct spx_boundary_object){{{address.value},{permission}U,{extent.value}}};'])
    if locals or record_locals:
        declarations.append(f'static struct spx_boundary_object boundary_locals[{len(locals)+len(record_locals)}];')
    for i, row in enumerate([*locals,*record_locals]):
        target = f'boundary_locals[{i}]'; initialize(row, target)
        args=(row['type_id'],target+'.address',target+'.extent',row['permissions'])
        if 'layout' in row:
            record_bindings[row['id']] = LocalRecordBinding(*args,row['layout'])
        else:
            bindings[row['id']] = LocalBytesBinding(*args)
    orders = []
    for i, service in enumerate(services):
        source = next(s for s in source_services if s['id'] == service['id'])
        surface = next(s for s in bundle.interface.services if s.identity == service['id'])
        signature = bundle.intent.schema.signature_index[surface.signature_id]
        order = [v.identity for v in signature.parameters if
                 (v.interpretation == 'view' and source['views'][v.identity] in bindings)
                 or v.identity in source.get('records',{})]
        orders.append(order)
        require(isinstance(service['objects'], list) and len(service['objects']) <= capacity, 'invalid service objects')
        for j, row in enumerate(service['objects']):
            require(set(row)-{'initializes','at'} == {'address', 'extent', 'permissions', 'local_view', 'parameter'}, 'object fields differ')
            require('at' not in row or row['at']=='call', 'unsupported object evaluation phase')
            initialization_spans(row)
            if row['local_view'] is not None:
                require(row['local_view'] in {**bindings,**record_bindings} and row['parameter'] in order
                        and {**source['views'],**source.get('records',{})}[row['parameter']] == row['local_view'],
                        'local object parameter differs')
            if row.get('at')=='call':
                require(row['local_view'] is None and row['parameter'] is None, 'call-time objects need checked scalar bindings')
                call_time=True
            else:
                initialize(row, f'boundary_objects[{i}][{j}]')
    return {'declarations': declarations, 'initializers': initializers, 'bindings': bindings,
            'record_bindings':record_bindings, 'orders': orders,
            'capacity': capacity, 'byte_capacity': min(256, definition.get('private_byte_capacity', 64)) or 64,
            'call_time': call_time}


def callback_objects(layout, index, service, *, lower=None):
    """Construct the original and source footprint at the actual invocation."""
    order = layout['orders'][index]
    count = len(service['objects'])
    lines = [f'struct spx_paired_object objects[{max(1, count)}];']
    if order:
        lines += [f'if(e->side==1U){{__CPROVER_assert(local_count=={len(order)}U,"spx-caller-local-argument-count");',
                  f'__CPROVER_assume(local_count=={len(order)}U);}}']
    for j, row in enumerate(service['objects']):
        name = f'object_{j}'
        if row.get('at')=='call':
            require(lower is not None, 'call-time footprint lacks checked relation bindings')
            address,extent=lower(row['address']),lower(row['extent'])
            require(address.sort==U32 and extent.sort in {U32,RelationSortV1('bitvector',width=64)}
                    and type(row['permissions']) is int and row['permissions'] in {1,2,3}, 'invalid call-time span')
            lines.extend([f'__CPROVER_assert({address.defined} && {extent.defined},"spx-caller-call-object-defined");',
                f'const struct spx_boundary_object object_value_{j}={{{address.value},{row["permissions"]}U,{extent.value}}};',
                f'const struct spx_boundary_object *{name}=&object_value_{j};'])
        else:
            lines.append(f'const struct spx_boundary_object *{name}=&boundary_objects[{index}][{j}];')
        local = row['local_view'] is not None
        lines.append(f'objects[{j}]=(struct spx_paired_object){{{name}->address,{name}->permissions,{int(local)}U,{name}->extent,0}};')
        if local:
            lines += [f'if(e->side==0U) objects[{j}].bytes=spx_caller_private_bytes(e->memory,{name}->address,{name}->extent,{name}->permissions);',
                f'else{{objects[{j}]=local_objects[{order.index(row["parameter"])}];',
                f'__CPROVER_assert(objects[{j}].local==1U && objects[{j}].address=={name}->address &&',
                f' objects[{j}].extent=={name}->extent && objects[{j}].permissions=={name}->permissions,"spx-caller-local-argument-binding");}}']
        else:
            lines.append(f'if(e->side==0U)spx_caller_public_span(e->memory,{name}->address,{name}->extent);')
    return lines


def initialization_spans(row):
    spans = row.get('initializes', [])
    require(isinstance(spans, list), 'object initialization spans must be a list')
    previous = 0
    for span in spans:
        require(isinstance(span, dict) and set(span) == {'offset', 'extent'}
                and all(type(span[k]) is int for k in span) and span['offset'] >= previous
                and span['extent'] > 0 and span['offset'] + span['extent'] <= 0xffffffff
                and row['permissions'] & 2 and row['parameter'] is not None,
                'object initialization requires ordered writable parameter spans')
        previous = span['offset'] + span['extent']
    return spans


def callback_object_initialization(service, *, terminal_outcomes=False):
    """Transport only supplier-proved spans, after a successful paired call."""
    lines = []
    for index, row in enumerate(service['objects']):
        for span in initialization_spans(row):
            if row['local_view'] is None:
                continue
            offset, extent = span['offset'], span['extent']
            guard = 'e->side==0U && !outcome.fault' + (' && !outcome.terminal' if terminal_outcomes else '')
            lines += [f'if({guard}){{',
                f'__CPROVER_assert(UINT64_C({offset+extent})<=objects[{index}].extent,"spx-caller-initialization-span");',
                f'__CPROVER_assume(UINT64_C({offset+extent})<=objects[{index}].extent);',
                f'spx_caller_initialize_private_bytes(e->memory,objects[{index}].address+{offset}U,UINT64_C({extent}));', '}']
    return lines
