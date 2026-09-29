"""Interface-derived portable adapters for the finite caller rule.

Signatures come from the compiled interface; service correspondence comes from
the enclosing checked rule. Neither a signature nor a view descriptor supplies
contents, termination, lifetime or a service guarantee. C bindings are internal.
"""

import json

from .bisimulation_call_relations import ScalarBinding, ViewBinding, lower_call_relation
from .bisimulation_caller_memory import U32
from .bisimulation_local_bytes import LocalBytesBinding, source_local_bytes_runtime
from .bisimulation_caller_local_records import (LocalRecordBinding, local_record_runtime,
                                               pack_local_records, unpack_local_records)
from .component_c_v5 import _c, _parameter_type, _result_type
from .relation_ir import RelationSortV1


VIEW_FIELDS = ('base.domain', 'base.object', 'base.generation', 'base.offset',
    'base.extent', 'base.permissions', 'extent', 'element_width', 'context',
    'access_context', 'read_u8', 'write_u8', 'read', 'write')


def require(value, message):
    if not value:
        raise ValueError('caller interface: '+message)


def _u32(types, value):
    t=types[value.type_id]
    return value.interpretation=='value' and t.kind=='integer' and t.body=={'signed':False,'width_bits':32}


def _unsigned_argument(types, value):
    t=types[value.type_id]
    return (value.interpretation=='value' and t.kind=='integer' and t.body.get('signed') is False
            and t.body.get('width_bits') in {8,16,32})


def _view(types, value):
    t=types[value.type_id]
    return (value.interpretation=='view' and t.kind=='pointer'
            and types[t.body['pointee_type_id']].kind=='integer'
            and types[t.body['pointee_type_id']].body=={'signed':False,'width_bits':8})


def caller_view_bindings(bundle, operation_id, *, record_types=()):
    """One ordered inventory for parameter and persistent-context byte views.

    State names are qualified to keep them distinct from operation parameters.
    Contents still come from the checked physical mapping and current shared
    world. A descriptor is framed; its writable backing bytes may change.
    """
    operation, = [op for op in bundle.interface.operations if op.identity == operation_id]
    signature = bundle.intent.schema.signature_index[operation.signature_id]
    result = [(v.identity, v) for v in signature.parameters if v.interpretation == 'view']
    for state in bundle.interface.state:
        value = state.value
        if (value.type_id in record_types and value.interpretation == 'value'
                and bundle.intent.schema.type_index[value.type_id].kind == 'opaque'):
            require(state.initial is None, 'record state has no checked initial-value claim')
            continue
        require('state.' + value.identity not in {v.identity for v in signature.parameters},
                'caller state name collides with an operation parameter')
        require(state.initial is None and _view(bundle.intent.schema.type_index, value)
                and value.nullable is False and value.extent['kind'] == 'fixed'
                and value.access in {'read', 'read_write'},
                'caller state needs a live fixed readable byte view with no initial-value claim')
        result.append(('state.' + value.identity, value))
    require(len({name for name, _ in result}) == len(result), 'caller view names collide')
    return result


def source_view_storage_runtime(view_count):
    """Snapshot and check the original live backing objects, not a replaced chain."""
    require(type(view_count) is int and 1<=view_count<=32, 'unsupported view count')
    return [
        'struct spx_caller_view_storage {spx_component_view_context *context;spx_runtime *runtime;struct spx_mutable_domain *domain;uint32_t address;uint64_t extent;uint32_t permissions;};',
        f'static struct spx_caller_view_storage view_storage[{view_count}];',
        'static uint32_t spx_caller_view_storage_ok(uint32_t index){',
        f'__CPROVER_assert(index<{view_count}U,"spx-source-view-storage-index");',
        'const struct spx_caller_view_storage *s=&view_storage[index];',
        'return s->context->runtime==s->runtime && s->context->address==s->address && s->context->extent==s->extent && s->context->permissions==s->permissions &&',
        's->runtime->context==s->domain && s->runtime->read==spx_mutable_read && s->runtime->write==spx_mutable_write &&',
        's->domain->world==&right && s->domain->address==s->address && s->domain->extent==s->extent && s->domain->permissions==s->permissions;',
        '}']


def source_service_adapters(bundle, operation_id, definitions, *, callbacks, result_views=None, local_views=None,
                            returned_views=None, records=None, local_records=None):
    """Instantiate declared scalar/view services; reject missing or extra bindings.

Each service view names its corresponding operation view. Compare every physical
descriptor and hook against an independent snapshot before using the associated
physical address. The sparse world behind that address retains current contents.

``result_views`` is a checker-owned service-to-operation-view map, to be derived
from validated supplier results. It transports a whole existing live view only:
no allocation, narrowing, lifetime extension or NUL guarantee is inferred. The
callback still checks the paired invocation and updates the shared byte world;
its returned native address must agree before the descriptor is transported.

``local_views`` supplies checker-owned physical bindings for scoped C byte views.
Their live bytes, hooks and metadata are checked at each call. Callbacks receiving
local views additionally receive a paired-object array and its count. The enclosing
rule must still prove the original storage relation and supplier applicability.
"""
    schema=bundle.intent.schema
    types=schema.type_index
    record_types=records.types if records else ()
    is_record=lambda v: v is not None and v.interpretation=='value' and types[v.type_id].kind=='opaque' and v.type_id in record_types
    view_bindings=caller_view_bindings(bundle,operation_id,record_types=record_types)
    views=[name for name,_ in view_bindings]
    local_views={} if local_views is None else local_views
    local_records={} if local_records is None else local_records
    require(isinstance(local_records,dict) and not set(local_records)&(set(local_views)|set(views))
            and all(isinstance(binding,LocalRecordBinding) for binding in local_records.values())
            and (not local_records or records is not None), 'invalid checked local record bindings')
    require(isinstance(local_views,dict) and not set(local_views)&set(views) and len(local_views)<=32
            and all(isinstance(name,str) and name and isinstance(binding,LocalBytesBinding)
                    and binding.type_id in types and type(binding.permissions) is int and binding.permissions in {1,2,3}
                    and isinstance(binding.address,str) and binding.address
                    and isinstance(binding.extent,str) and binding.extent
                    for name,binding in local_views.items()), 'invalid checked local view bindings')
    require(isinstance(definitions,list) and all(isinstance(d,dict) for d in definitions), 'invalid service inventory')
    services={s.identity:s for s in bundle.interface.services}
    require(len(definitions)==len(services) and {d.get('id') for d in definitions}==set(services),
            'service coverage differs')
    require(set(callbacks)==set(services), 'checked service callbacks differ')
    result_views={} if result_views is None else result_views
    returned_views={} if returned_views is None else returned_views
    require(isinstance(returned_views,dict) and set(returned_views)<=set(services)
            and not set(returned_views)&set(result_views), 'returned view rules conflict')
    require(isinstance(result_views,dict) and set(result_views)<=set(services)
            and all(isinstance(v,str) and v in views for v in result_views.values()),
            'checked result view correspondence differs')
    lines=['static uint32_t spx_caller_same_view(const spx_view_v5 *a,const spx_view_v5 *b){',
           ' return '+ ' && '.join(f'a->{f}==b->{f}' for f in VIEW_FIELDS)+';','}']
    if local_views:
        lines.append(source_local_bytes_runtime())
    if local_records:
        lines.extend(local_record_runtime(local_records))
    names={}
    for position,row in enumerate(sorted(definitions,key=lambda d:d['id'])):
        require(set(row)-{'records'}=={'id','views','arguments','diagnostic'}, 'service definition fields differ')
        require(isinstance(row['diagnostic'],str), 'invalid diagnostic')
        signature=schema.signature_index[services[row['id']].signature_id]
        require(len(signature.results)<=1, 'unsupported service result')
        result=signature.results[0] if signature.results else None
        returned_view=result is not None and _view(types,result)
        dynamic=row['id'] in returned_views
        require(((result is None or _u32(types,result) or is_record(result)) and row['id'] not in result_views and not dynamic)
                or (returned_view and (row['id'] in result_views or dynamic)), 'unsupported service result')
        if dynamic:
            rule=returned_views[row['id']]
            require(result.nullable is False and result.extent['kind']=='fixed' and result.extent['bytes']==rule['extent']
                    and {'read':1,'write':2,'read_write':3}.get(result.access)==rule['permissions'],
                    'returned service view contract differs')
        elif returned_view:
            provided=dict(view_bindings)[result_views[row['id']]]
            require(_view(types,provided) and provided.type_id==result.type_id
                    and provided.nullable is False and result.nullable is False
                    and provided.access==result.access
                    and provided.provider_domain==result.provider_domain
                    and provided.resource_kind==result.resource_kind,
                    'returned view type/permissions/domain differ')
            # A service may change bytes, so even an incoming terminated view
            # cannot establish a terminated result. Only fixed byte spans have
            # an implemented whole-view transport here; other extent contracts
            # need their own checked result rule.
            require(result.extent['kind']=='fixed', 'returned view extent requires a checked rule')
        require(all(_u32(types,v) or _view(types,v) or is_record(v) for v in signature.parameters), 'unsupported service parameter')
        require(isinstance(row['views'],dict) and set(row['views'])=={
            v.identity for v in signature.parameters if v.interpretation=='view'}
            and all(v in views or v in local_views for v in row['views'].values()), 'service view correspondence differs')
        require(isinstance(row['arguments'],list) and len(row['arguments'])<=32, 'invalid projected arguments')
        name=f'spx_source_service_{position}'
        names[row['id']]=name
        params=['void *opaque',*(f'{_parameter_type(types,v)} p{i}' for i,v in enumerate(signature.parameters))]
        lines.extend([f'static {_result_type(types,signature)} {name}('+','.join(params)+'){',
                      ' struct environment *e=opaque;'])
        bindings={}
        local_parameters=[]
        record_parameters=[]
        record_mapping=row.get('records',{})
        require(isinstance(record_mapping,dict) and set(record_mapping)<={v.identity for v in signature.parameters}
                and all(name in local_records for name in record_mapping.values()), 'local record correspondence differs')
        for i,value in enumerate(signature.parameters):
            if value.identity in record_mapping:
                binding=local_records[record_mapping[value.identity]]
                require(is_record(value) and value.type_id==binding.type_id and not value.nullable,
                        'local record parameter type/nullability differs')
                record_parameters.append((i,value,binding))
            if value.interpretation=='view' and row['views'][value.identity] in local_views:
                binding=local_views[row['views'][value.identity]]
                permission={'read':1,'write':2,'read_write':3}.get(value.access)
                require(value.type_id==binding.type_id and permission is not None
                        and (permission&binding.permissions)==permission, 'local service view type/permissions differ')
                local_parameters.append((i,value,binding,permission))
        local_order=sorted([i for i,*_ in local_parameters]+[i for i,*_ in record_parameters])
        if local_order:
            require(not returned_view, 'local returned view requires a separate lifetime rule')
            lines.append(f' struct spx_paired_object local_objects[{len(local_order)}];')
        local_index={i:j for j,(i,*_) in enumerate(local_parameters)}
        object_index={i:j for j,i in enumerate(local_order)}
        record_index={i:binding for i,_,binding in record_parameters}
        for i,value in enumerate(signature.parameters):
            if value.interpretation=='view':
                if i in local_index:
                    _,_,binding,permission=local_parameters[local_index[i]]
                    lines.extend([
                        f' local_objects[{object_index[i]}]=spx_source_local_bytes(p{i},{binding.address},{binding.extent},{permission}U);',
                        f' spx_view_v5 local_view_{i}=*p{i};',
                        f' spx_local_bytes_v5 local_owner_{i}=*(const spx_local_bytes_v5 *)p{i}->access_context;'])
                    if value.extent['kind']=='fixed':
                        lines.append(f' __CPROVER_assert(p{i}->extent=={value.extent["bytes"]}U,"spx-source-local-fixed-extent");')
                    else:
                        require(value.extent['kind']=='none', 'local service extent requires a checked rule')
                    bindings[value.identity]=ViewBinding(RelationSortV1('view',type_id=value.type_id),
                        binding.address,f'p{i}->extent','')
                    continue
                index=views.index(row['views'][value.identity])
                lines.append(f' __CPROVER_assert(spx_caller_same_view(p{i},&expected_views[{index}]),{json.dumps(row["diagnostic"])});')
                lines.append(f' __CPROVER_assert(spx_caller_view_storage_ok({index}U),"spx-source-view-storage");')
                bindings[value.identity]=ViewBinding(RelationSortV1('view',type_id=value.type_id),
                    f'((const spx_component_view_context *)expected_views[{index}].access_context)->address',
                    f'expected_views[{index}].extent','')
            elif is_record(value):
                if not value.nullable:
                    lines.append(f' __CPROVER_assert(p{i}!=0,"spx-source-record-argument-nonnull");')
                bindings[value.identity]=ScalarBinding(U32,record_index[i].address if i in record_index else
                                                       records.encode(value.type_id,f'p{i}'))
            else:
                bindings[value.identity]=ScalarBinding(U32,f'p{i}')
        lines.extend(pack_local_records(record_parameters,object_index))
        for i,_,_ in record_parameters:
            for j,_,_,_ in local_parameters:
                lines.append(f'__CPROVER_assert(!__CPROVER_same_object(p{i},local_objects[{object_index[j]}].bytes),'
                             '"spx-local-record-byte-view-overlap");')
        args=[]
        for i,raw in enumerate(row['arguments']):
            # Service projection does not have a current-memory accessor. Memory
            # reads occur through the actual ordinary C and generated view hooks.
            value=lower_call_relation(raw,parameters=bindings)
            require(value.sort==U32, 'unsupported projected argument sort')
            lines.append(f' __CPROVER_assert({value.defined},"spx-source-service-argument-defined");')
            lines.append(f' uint32_t arg{i}={value.value};')
            args.append(f'arg{i}')
        extra=['local_objects',f'{len(local_order)}U'] if local_order else []
        call=f'{callbacks[row["id"]]}('+','.join(['e',*args,*extra])+')'
        if record_parameters:
            lines.append(f'uint32_t local_record_result={call};')
            lines.extend(unpack_local_records(record_parameters))
            call='local_record_result'
        if is_record(result):
            require(not local_parameters, 'local byte storage and record return need a checked combined lifetime')
            lines.append(f' uint32_t returned_address={call};')
            if not result.nullable:
                lines.append(' __CPROVER_assert(returned_address!=0U,"spx-source-record-result-nonnull");')
            lines.extend([' return '+records.decode(result.type_id,'returned_address')+';','}'])
        elif dynamic:
            lines.extend([f' uint32_t returned_address={call};',
                          ' return spx_returned_source_view(returned_address);','}'])
        elif returned_view:
            index=views.index(result_views[row['id']])
            lines.extend([f' uint32_t returned_address={call};',
                f' __CPROVER_assert(spx_caller_same_view(&e->views[{index}],&expected_views[{index}]),"spx-source-returned-view-frame");',
                f' __CPROVER_assert(spx_caller_view_storage_ok({index}U),"spx-source-returned-view-storage");',
                f' __CPROVER_assert(expected_views[{index}].extent=={result.extent["bytes"]}U,"spx-source-returned-view-extent");',
                f' __CPROVER_assert(returned_address==((const spx_component_view_context *)expected_views[{index}].access_context)->address,"spx-source-returned-view-address");',
                f' return e->views[{index}];','}'])
        elif local_parameters:
            lines.append(f' uint32_t result={call};')
            for i,_,_,_ in local_parameters:
                lines.extend([
                    f' __CPROVER_assert(spx_caller_same_view(p{i},&local_view_{i}),"spx-source-local-view-frame");',
                    f' __CPROVER_assert(spx_source_local_owner_equal(local_view_{i}.access_context,&local_owner_{i}),"spx-source-local-owner-frame");'])
            lines.extend([' return result;' if result is not None else ' (void)result; return;','}'])
        else:
            lines.extend([f' return {call};' if result is not None else f' (void){call}; return;','}'])
    return '\n'.join(lines)+'\n',names


def source_operation_invocation(bundle, operation_id, symbol, *, arguments, callbacks,
                                result_name, diagnostic, observe_frame=False, records=None):
    """Use the generated ABI for a stateless operation and check its whole context.

Arguments, callback symbols and result_name are checker bindings, not public C.
Stateful protocols require a checked state relation and are explicitly unsupported.
"""
    interface=bundle.interface
    schema=bundle.intent.schema
    component=_c(interface.identity)
    operation,=[op for op in interface.operations if op.identity==operation_id]
    signature=schema.signature_index[operation.signature_id]
    require(len(interface.protocol_states)==1,
            'stateful caller context requires a checked transport rule')
    record_types=records.types if records else ()
    views=caller_view_bindings(bundle,operation_id,record_types=record_types)
    require(set(arguments)=={v.identity for v in signature.parameters}, 'operation argument coverage differs')
    require(set(callbacks)=={s.identity for s in interface.services}, 'operation service coverage differs')
    require(len(signature.results)<=1, 'at most one operation result is supported')
    require(all(_unsigned_argument(schema.type_index,v) or _view(schema.type_index,v)
                or (v.interpretation=='value' and v.type_id in record_types and schema.type_index[v.type_id].kind=='opaque')
                for v in signature.parameters),
            'unsupported operation parameter')
    require(type(observe_frame) is bool, 'source frame observation must be Boolean')
    protocol=f'SPX_{component.upper()}_PROTOCOL_{_c(interface.protocol_states[0]).upper()}'
    services=', '.join(f'.{_c(k)}={v}' for k,v in sorted(callbacks.items()))
    state_initializers=''
    if interface.state:
        state_initializers=',.state={'+','.join(
            f'.{_c(state.value.identity)}='+ (records.state[state.value.identity] if records and state.value.identity in records.state else
                f'env_right.views[{[name for name,_ in views].index("state."+state.value.identity)}]')
            for state in interface.state)+'}'
    invoke=(f'spx_{component}_services_v5 services={{.context=&env_right, {services}}};\n'
        f'spx_{component}_context_v5 context={{.services=&services,.protocol_state={protocol}{state_initializers}}};\n'
        + ('spx_caller_context=&context;spx_caller_services=&services;spx_caller_environment=&env_right;\n'
           if observe_frame else '') +
        (f'{_result_type(schema.type_index,signature)} {_c(result_name)}=' if signature.results else '')+
        f'{_c(symbol)}('
        +','.join(['&context',*(arguments[v.identity] for v in signature.parameters)])+');\n')
    frame = ('spx_caller_source_frame();\n' if observe_frame else
             _source_operation_frame(bundle, operation_id, callbacks, diagnostic, records=records))
    return invoke,frame


def _source_operation_frame(bundle, operation_id, callbacks, diagnostic, *,
                            context='context', services='services', environment='env_right', records=None):
    interface=bundle.interface
    component=_c(interface.identity)
    protocol=f'SPX_{component.upper()}_PROTOCOL_{_c(interface.protocol_states[0]).upper()}'
    views=caller_view_bindings(bundle,operation_id,record_types=records.types if records else ())
    checks=[f'{context}.services==&{services}',f'{context}.protocol_state=={protocol}',
            f'{services}.context==&{environment}',
            *(f'{services}.{_c(k)}=={v}' for k,v in sorted(callbacks.items()))]
    if not interface.state:
        checks.append(f'{context}.state.reserved==0U')
    if records:
        checks += [f'{context}.state.{_c(name)}=={pointer}' for name,pointer in records.state.items()]
    frame='__CPROVER_assert('+ ' && '.join(checks)+','+json.dumps(diagnostic)+');\n'
    for i,(name,_) in enumerate(views):
        if name.startswith('state.') and name in {'state.'+s.value.identity for s in interface.state}:
            frame+=f'__CPROVER_assert(spx_caller_same_view(&{context}.state.{_c(name.removeprefix("state."))},&expected_views[{i}]),"spx-source-state-view-frame");\n'
        frame+=f'__CPROVER_assert(spx_caller_same_view(&{environment}.views[{i}],&expected_views[{i}]),"spx-source-view-frame");\n'
        frame+=f'__CPROVER_assert(spx_caller_view_storage_ok({i}U),"spx-source-view-storage");\n'
    if records:
        frame+='spx_record_frame();\n__CPROVER_assert(right.representation==0 && right.read_representation==spx_record_read && right.write_representation==spx_record_apply,"spx-record-world-frame");\n'
    return frame


def source_operation_frame_runtime(bundle, operation_id, *, callbacks, diagnostic, records=None):
    """Check the same live source context on both normal and terminal exits.

    The invocation captures the actual automatic objects before calling authored
    C. A stopping service can therefore check them while their lifetimes remain
    active; it cannot hide earlier context, service-table or view corruption.
    """
    component=_c(bundle.interface.identity)
    return '\n'.join([
        f'static spx_{component}_context_v5 *spx_caller_context;',
        f'static spx_{component}_services_v5 *spx_caller_services;',
        'static struct environment *spx_caller_environment;',
        'static void spx_caller_source_frame(void){',
        _source_operation_frame(bundle, operation_id, callbacks, diagnostic,
            context='(*spx_caller_context)', services='(*spx_caller_services)',
            environment='(*spx_caller_environment)',records=records), '}'])+'\n'
