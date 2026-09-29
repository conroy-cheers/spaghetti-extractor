"""Checked finite caller definitions over existing interfaces and relation IR.

Definitions select scope, admission and observations. Supplier guarantees are
sealed from current checked facts; runtime service contracts remain named,
explicitly unverified assumptions. No target name or full-interface hash selects
semantics here. Definitions contain neither C bodies nor compiler commands.
"""
from copy import deepcopy

from .bisimulation_caller_memory import checked_native_memory
from .bisimulation_call_relations import constant
from .bisimulation_native_calls import checked_return
from .bisimulation_caller_targets import captured_call_target
from .bisimulation_supplier_call import instantiate_supplier_call, instantiate_borrowed_supplier_call, substitute_parameters
from .bisimulation_caller_boundary import BYTES, any_of, named, negate
from .bisimulation_call_relations import parameter
from .relation_ir import RelationExpressionV1
from .bisimulation_supplier_facts import BORROWED_RULE, check_supplier_service
from .bisimulation_caller_interface import caller_view_bindings
from .interface_package_v5 import compile_component_interface_v5

from .caller_definition_document import PROFILE, checked_caller_document
PROOF_ENTRY='spx_check_caller'


def require(value,message):
    if not value:raise ValueError('caller definition: '+message)


def selected_definition(contract):
    checked_caller_document(contract)
    units=contract['unit_rvas'];entry=contract['entry_rva']
    boundary=deepcopy(contract['boundary'])
    boundary.update(entry=entry,operation=contract['operation_id'],proof_entry=PROOF_ENTRY)
    return {'component':contract['component_id'],'entry':entry,'units':units,'operation':contract['operation_id'],
        'proof_entry':PROOF_ENTRY,'required_frame':contract.get('required_frame'),
        'native_memory':checked_native_memory(contract['native_memory']),'boundary':boundary}


def checked_caller_interface(intent, operation_id, source_services, *, local_views=(), local_records=(), record_types=()):
    interface=intent.to_payload()
    require(not interface['effects'] and len(interface['protocol']['states'])==1
            and len(interface['operations'])==1,'stateful/effectful interfaces need a checked transport rule')
    operation,=interface['operations'];state=interface['protocol']['states'][0]
    require(operation['id']==operation_id and operation['pre_states']==operation['post_states']==[state]
            and interface['protocol']['initial_state']==state,'operation protocol differs')
    require(not operation['effect_ids'] and not operation['lifecycle_bindings']
            and not operation['checked_interaction_contract_ids']
            and operation['lifecycle_additional_roots']=={'state':[row['value'] for row in interface['state']]},
            'operation effects/lifecycle require a checked composition rule')
    signature=intent.schema.signature_index[operation['signature_id']].to_payload()
    projections=[{'source_id':v['id'],'target':{'root':root,'value_id':v['id'],'fields':[]}}
                 for root,key in [('parameter','parameters'),('result','results')] for v in signature[key]]
    require(operation['projection_entries']==projections and operation['source_values']==signature['parameters']+signature['results'],
            'operation value transport requires a checked projection rule')
    services={row['id']:row for row in interface['services']}
    require(isinstance(source_services,list) and len(source_services)==len(services)
            and {row['id'] for row in source_services}==set(services)==set(operation['allowed_service_ids']),
            'operation/service coverage differs')
    parameters={row['id']:row for row in signature['parameters']}
    for name,value in caller_view_bindings(compile_component_interface_v5(intent),operation_id,record_types=record_types):
        if name not in parameters:
            parameters[name]=value.to_payload()
    permissions={'read':1,'write':2,'read_write':3}
    local={row['id']:row for row in local_views}
    local_record={row['id']:row for row in local_records}
    for row in source_services:
        require(set(row)-{'records'}=={'id','views','arguments','diagnostic'}, 'service definition fields differ')
        service=services[row['id']]
        require(not service['effect_ids'],'service effects need a checked composition rule')
        used=intent.schema.signature_index[service['signature_id']].to_payload()
        record_parameters=row.get('records',{})
        require(isinstance(record_parameters,dict), 'local record mapping must be an object')
        used_parameters={v['id']:v for v in used['parameters']}
        for name,mapped in record_parameters.items():
            require(name in used_parameters and mapped in local_record, 'local record parameter is absent')
            needed=used_parameters[name];provided=local_record[mapped]
            require(needed['interpretation']=='value' and needed['nullable'] is False
                    and needed['type_id']==provided['type_id'] and needed['type_id'] in record_types,
                    'local record type or nullability differs')
        views={v['id']:v for v in used['parameters'] if v['interpretation']=='view'}
        require(set(row['views'])==set(views),'service view coverage differs')
        for name,mapped in row['views'].items():
            if mapped in local:
                provided=local[mapped];needed=views[name]
                require(provided['type_id']==needed['type_id']
                        and provided['permissions']&permissions.get(needed['access'],0)==permissions.get(needed['access'],0)
                        and needed['extent']['kind'] in {'none','fixed'}, 'local service view contract differs')
                continue
            require(mapped in parameters,'service view is not an operation parameter or checked state view')
            provided=parameters[mapped];needed=views[name]
            require(provided['interpretation']=='view' and provided['type_id']==needed['type_id']
                    and provided['nullable'] is False and needed['nullable'] is False
                    and permissions.get(provided['access'],0)&permissions.get(needed['access'],0)==permissions.get(needed['access'],0),
                    'service view permissions/type/nullability differ')
            require(provided['provider_domain']==needed['provider_domain'] and provided['resource_kind']==needed['resource_kind'],
                    'service view resource domain differs')
    return signature


def instantiate_definition(contract, selected, facts, intent):
    from .bisimulation_object_call import OBJECT_CALL_RULE
    from .bisimulation_caller_summary import CALLER_CALL_RULE
    if 'suppliers' in contract:
        require(set(facts)==set(contract['suppliers']) and all(f['rule'] in {OBJECT_CALL_RULE,CALLER_CALL_RULE} for f in facts.values()),
                'multiple checked suppliers require a supported paired composition rule')
        from .bisimulation_caller_objects import instantiate_object_definition
        return instantiate_object_definition(contract,selected,facts,intent)
    if facts['rule']==OBJECT_CALL_RULE:
        from .bisimulation_caller_objects import instantiate_object_definition
        return instantiate_object_definition(contract,selected,facts,intent)
    require(facts['rule']!=CALLER_CALL_RULE, 'finite callable suppliers use the explicit supplier map')
    boundary=selected['boundary'];services=deepcopy(contract['source_services'])
    require(not any(row['storage']=='private_bytes' for row in selected['native_memory']),
            'caller-local byte storage needs checked supplier effects and lifetime composition')
    borrowed=facts['rule']==BORROWED_RULE
    require(not borrowed or contract['witnesses']=={}, 'borrowed supplier accepts no cleanup witnesses')
    admission=boundary.pop('supplier_admission',None)
    if admission is not None:
        require(isinstance(admission,dict) and set(admission)=={'guard','bindings'}
                and isinstance(admission['bindings'],dict),'supplier admission reference differs')
        bindings={name:RelationExpressionV1.parse(value) for name,value in admission['bindings'].items()}
        require('entry_memory' not in bindings,'entry memory binding must be derived')
        bindings['entry_memory']=parameter('entry_memory',BYTES)
        guard=None if admission['guard'] is None else RelationExpressionV1.parse(admission['guard'])
        premises=[]
        for row in facts['entry_relations']:
            predicate=substitute_parameters(row['expression'],bindings)
            premises.append(named(row['id'],predicate if guard is None else any_of(negate(guard),predicate)))
        boundary['admission']=[*premises,*boundary['admission']]
    require('records' not in boundary, 'records require explicit object footprints')
    checked_caller_interface(intent,selected['operation'],services)
    check_supplier_service(facts,intent,contract['service_id'])
    supplier_service,=[row for row in services if row['id']==contract['service_id']]
    state_views={}
    for i,view in enumerate(boundary['views']):
        if 'supplier_view' not in view:continue
        require(set(view)=={'id','supplier_view'} and view['supplier_view'] in facts['native_projection']['image_views']
                and (borrowed or supplier_service['views'].get(view['supplier_view'])==view['id']),'supplier view reference differs')
        physical=facts['native_projection']['image_views'][view['supplier_view']]
        require(view['supplier_view'] not in state_views,'duplicate supplier view mapping')
        state_views[view['supplier_view']]=view['id']
        if borrowed:
            provided=dict(caller_view_bindings(compile_component_interface_v5(intent),selected['operation']))[view['id']]
            state=next(s['value'] for s in facts['interface_intent']['state'] if s['value']['id']==view['supplier_view'])
            require({**provided.to_payload(),'id':state['id']}==state,'borrowed state view contract differs')
        boundary['views'][i]={'id':view['id'],'address':constant(physical['address']).to_payload(),
                              'extent':constant(physical['extent']).to_payload()}
    require(not borrowed or set(state_views)==set(facts['native_projection']['image_views']),
            'borrowed supplier state view coverage differs')
    calls=deepcopy(contract['native_calls']);runtime=deepcopy(contract['runtime_contracts'])
    service_index={row['id']:row for row in services}
    from .bisimulation_native_calls import checked_call_sites
    arities=checked_call_sites(calls,set(service_index))
    require(isinstance(runtime,dict) and set(runtime)==set(service_index)-{contract['service_id']},'runtime authority coverage differs')
    outcomes={}
    for i,row in enumerate(calls):
        require(set(row)=={'id','event','arguments','requires','entry_stack_delta'}, 'native call fields differ; guarantees must be derived')
        if row['id']==contract['service_id']:
            require(row['event']['kind']=='internal' and row['event']['target_rva']==facts['original_entry_rva'],
                    'supplier event target differs')
            if borrowed:
                calls[i]=instantiate_borrowed_supplier_call(facts,boundary,row,service_index[row['id']],selected['native_memory'])
                outcomes[row['id']]={'fault':'none','normal_excludes':[],
                    'result_view':state_views[facts['result_view']['state_id']],
                    'result_value':constant(facts['result_view']['address']).to_payload()}
            else:
                calls[i]=instantiate_supplier_call(facts,boundary,row,service_index[row['id']],contract['witnesses'])
                outcomes[row['id']]={'fault':'uint32-max','normal_excludes':facts['normal_excludes']}
        else:
            premise=runtime[row['id']]
            require(isinstance(premise,dict) and set(premise)-{'captured_target_projection','target_sampling'}=={'id','revision','status','normal_return','fault','normal_excludes','requires','ensures','unverified'}
                    and isinstance(premise['id'],str) and premise['id'] and type(premise['revision']) is int and premise['revision']>0
                    and premise['status']=='unverified' and row['event']['kind'] in {'import','indirect'}, 'runtime service needs an explicit unverified import contract')
            require(all(isinstance(premise[k],str) and premise[k] for k in ('requires','ensures'))
                    and isinstance(premise['unverified'],list) and premise['unverified'], 'runtime assumptions must remain visible')
            row['normal_return']=checked_return(premise['normal_return'])
            outcomes[row['id']]={k:premise[k] for k in ('fault','normal_excludes')}
            target=captured_call_target(row,premise)
            if target is not None:outcomes[row['id']]['captured_target_projection']=target
            if 'target_sampling' in premise:outcomes[row['id']]['target_sampling']=premise['target_sampling']
    require(len(boundary['services'])==len(services) and {row['id'] for row in boundary['services']}==set(service_index),
            'boundary service coverage differs')
    for row in boundary['services']:
        require(not {'arguments','fault','normal_excludes','result_view','result_value','objects','terminal_services','captured_target_projection','target_sampling','returned_view'}&set(row),
                'service outcomes, footprints and arity must be derived')
        row.update(arguments=arities[row['id']],**outcomes[row['id']])
    return boundary,calls,services,{'id':PROFILE,'revision':1,'supplier':facts,'services':runtime,
        'scope':'Conditional selected operation only; caller reachability, concrete runtime applicability and activation are unverified.'}


def checked_caller_scope(original, selected, calls, transfer_plan_sha256):
    require(original['bindings']['executable_transfer_plan_sha256']==transfer_plan_sha256
            and original['root_entry_rvas']==[selected['entry']]
            and original['root_unit_ids']==original['root_context_unit_ids']
            and not original['forced_label_rvas'] and not original['dependency_components'], 'original operation scope differs')
    mapping={row['unit_id']:row['rva'] for row in original['source_map']}
    require(len(mapping)==len(original['source_map']) and len(original['root_unit_ids'])==len(set(original['root_unit_ids']))
            and {mapping[u] for u in original['root_unit_ids']}==set(selected['units']), 'original ownership has a hole, duplicate or extra unit')
    functions=[f for f in original['functions'] if selected['entry'] in f['entries']]
    require(len(functions)==1 and functions[0]['entries']==[selected['entry']]
            and functions[0]['unit_rvas']==selected['units'], 'original caller entry/function coverage differs')
    edges=[e for e in original['internal_direct_call_closure']['call_edges'] if e['source_rva'] in selected['units']]
    internal=[row['event'] for row in calls if row['event']['kind']=='internal']
    summaries=original['internal_direct_call_closure'].get('summary_entry_rvas',[])
    require(isinstance(summaries,list) and all(type(rva) is int for rva in summaries)
            and summaries==sorted(set(summaries)) and set(summaries)<={row['target_rva'] for row in internal},
            'original body boundary has no checked or explicit conditional call')
    keys=('source_rva','instruction_rva','return_rva','target_rva','call_index')
    require(len(edges)==len(internal) and sorted(tuple(e[k] for k in keys) for e in edges)==
            sorted(tuple(e[k] for k in keys) for e in internal),'original dependency edge coverage differs')
    require(all(row['event']['source_rva'] in selected['units'] for row in calls),'call originates outside owned scope')
    return {'entry_rva':selected['entry'],'unit_rvas':selected['units'],'operation_id':selected['operation']}
