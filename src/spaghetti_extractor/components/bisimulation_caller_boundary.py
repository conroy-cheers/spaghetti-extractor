"""Finite caller boundary instantiation over the existing relation and C engines.

Definitions describe the admitted interface and observations, not executable
target algorithms. Supplier/runtime guarantees are checker inputs and must be
validated before instantiation. A passing conditional query grants no activation.
"""
import json

from .bisimulation_call_relations import ScalarBinding, ViewBinding, constant, expression, lower_call_relation, parameter
from .bisimulation_caller_memory import U32, _entry_bindings, checked_native_memory, native_memory_initialization, native_memory_runtime
from .bisimulation_caller_interface import caller_view_bindings, source_operation_invocation, source_operation_frame_runtime, source_service_adapters, source_view_storage_runtime
from .bisimulation_caller_targets import source_target_lines, target_projection, entry_target_lines
from .bisimulation_caller_returned_views import returned_view_runtime, returned_view_candidate
from .bisimulation_caller_records import record_type_ids, render_record_transport
from .bisimulation_mutable_memory import sparse_mutable_memory_runtime
from .bisimulation_native_calls import register, render_native_calls
from .bisimulation_paired_calls import paired_call_runtime
from .capabilities import spx_portable_reference_runtime_v5_source
from .component_c_v5 import _c
from .machine_overlay_runtime_helpers import _view_runtime_helpers
from .relation_ir import BOOL_SORT, MachinePlaceV1, RelationExpressionV1, RelationSortV1

U64=RelationSortV1('bitvector',width=64)
BYTES=RelationSortV1('view',type_id='bytes')
ADMISSION_ENTRY='spx_check_boundary_admission'
ADMISSION_WITNESS='spx-boundary-admitted-entry-witness'


def require(value, message):
    if not value:raise ValueError('caller boundary: '+message)


def value(name, sort=U32):return parameter(name,sort)
def eq(a,b):return expression('eq',BOOL_SORT,a,b)
def le(a,b):return expression('ule',BOOL_SORT,a,b)
def lt(a,b):return expression('ult',BOOL_SORT,a,b)
def add(a,b):return expression('add',a.sort,a,b)
def sub(a,b):return expression('sub',a.sort,a,b)
def wide(a):return expression('zero_extend',U64,a) if a.sort==U32 else a
def negate(a):return expression('not',BOOL_SORT,a)
def choose(guard,a,b):return expression('ite',a.sort,guard,a,b)


def all_of(*args):
    result=expression('true',BOOL_SORT)
    for arg in args:result=expression('and',BOOL_SORT,result,arg)
    return result


def any_of(*args):return negate(all_of(*(negate(arg) for arg in args)))


def word(memory,address):
    # Four current byte observations, with a wide offset so the last byte cannot
    # silently wrap at 2^32. Contents come from the selected phase's sparse world.
    return expression('concat',U32,*(expression('byte_read',RelationSortV1('bitvector',width=8),
        value(memory,BYTES),add(wide(address),constant(i,64))) for i in reversed(range(4))))


def named(identity,predicate):return {'id':identity,'expression':predicate.to_payload()}


def field(name, *, phase='exit'):
    place=MachinePlaceV1.parse({'kind':'register','phase':phase,'width':32,'selector':{'register':name}})
    return RelationExpressionV1.parse({'op':'machine','sort':U32.to_payload(),'args':[],
                                      'attributes':{'place':place.to_payload()}})


def _assertions(rows,parameters,machines):
    require(isinstance(rows,list) and len(rows)<=256,'invalid assertion inventory')
    lines=[];seen=set()
    for row in rows:
        require(isinstance(row,dict) and set(row)=={'id','expression'} and isinstance(row['id'],str)
                and row['id'] not in seen,'invalid or duplicate assertion identity')
        seen.add(row['id'])
        predicate=lower_call_relation(row['expression'],parameters=parameters,machines=machines).predicate()
        lines.append(f'__CPROVER_assert({predicate},{json.dumps(row["id"])});')
    return '\n'.join(lines)+'\n'


def render_caller_boundary(definition, symbol, *, interface_bundle, native_memory, native_calls, source_services):
    """All C bindings below are checker-owned. No definition field accepts C."""
    d=definition
    require(isinstance(d,dict) and set(d)-{'result_view','private_byte_capacity','local_views','local_records','records'}=={'entry','proof_entry','operation','image_base','values','admission',
        'views','private_low','private_high','call_private_low','call_private_high','services','event_capacity',
        'call_capacity','assertions','outcomes','context_diagnostic','memory_diagnostic'},'definition fields differ')
    require(type(d['entry']) is int and 0<=d['entry']<2**32 and type(d['image_base']) is int
            and 0<=d['image_base']<2**32,'invalid original entry or image base')
    memory=checked_native_memory(native_memory)
    private_byte_capacity=d.get('private_byte_capacity',0)
    require(type(private_byte_capacity) is int and 0<=private_byte_capacity<=4096
            and bool(private_byte_capacity)==any(row['storage']=='private_bytes' for row in memory),
            'private byte storage needs an explicit checked capacity')
    operation,=[op for op in interface_bundle.interface.operations if op.identity==d['operation']]
    signature=interface_bundle.intent.schema.signature_index[operation.signature_id]
    record_types=record_type_ids(d,interface_bundle)
    view_parameters=caller_view_bindings(interface_bundle,d['operation'],record_types=record_types)
    require(isinstance(d['views'],list) and len(d['views'])==len(view_parameters) and
        {v['id'] for v in d['views']}=={name for name,_ in view_parameters},'view coverage differs')
    view_rows={v['id']:v for v in d['views']};view_count=len(view_rows)
    require(0<=view_count<=32,'unsupported view count')
    view_capacity=max(1,view_count)
    services=d['services'];require(isinstance(services,list) and 1<=len(services)<=32,'invalid services')
    ids=[r['id'] for r in services]
    terminal_outcomes=any('terminal_services' in row for row in services)
    code_targets=any('captured_target_projection' in row for row in services)
    returned_views={row['id']:row['returned_view'] for row in services if 'returned_view' in row}
    require(len(set(ids))==len(ids),'duplicate service identity')
    require(set(ids)=={row['id'] for row in source_services}=={row['id'] for row in native_calls},'call/service coverage differs')
    require(type(d['event_capacity']) is int and 1<=d['event_capacity']<=64,'invalid event bound')
    require(type(d['call_capacity']) is int and 1<=d['call_capacity']<=64,'invalid call bound')
    parameters={};declarations=[];initializers=[];seen=set();machines=_entry_bindings()
    machines[MachinePlaceV1.parse(register('df','entry').attributes['place']).key]=ScalarBinding(U32,'initial.df')
    memory_parameters={name:ViewBinding(BYTES,'0U','UINT64_C(4294967296)',accessor) for name,accessor in
        [('entry_memory','__CPROVER_uninterpreted_readonly_byte'),('original_memory','original_byte'),('source_memory','source_byte')]}
    require(isinstance(d['values'],list) and len(d['values'])<=64,'invalid incoming values')
    for row in d['values']:
        require(isinstance(row,dict) and set(row)=={'id','sort','expression'},'incoming value fields differ')
        name=_c(row['id']);sort=RelationSortV1.parse(row['sort'])
        require(name not in seen and row['id'] not in memory_parameters and sort in {U32,U64,BOOL_SORT},'invalid incoming value')
        seen.add(name);ctype='_Bool' if sort==BOOL_SORT else f'uint{sort.width}_t'
        declarations.append(f'{ctype} {name};')
        if row['expression'] is not None:
            lowered=lower_call_relation(row['expression'],parameters={**memory_parameters,**parameters},machines=machines)
            require(lowered.sort==sort,'incoming value sort differs')
            # Entry binding definedness is part of explicit conditional admission.
            initializers.append(f'__CPROVER_assume({lowered.defined});values.{name}={lowered.value};')
        parameters[row['id']]=ScalarBinding(sort,'values.'+name)
    entry_parameters={**memory_parameters,**parameters}
    lower=lambda raw,bindings=entry_parameters:lower_call_relation(raw,parameters=bindings,machines=machines)
    admissions=[]
    require(isinstance(d['admission'],list) and len(d['admission'])<=256,'invalid entry admission')
    for row in d['admission']:
        require(isinstance(row,dict) and set(row)=={'id','expression'},'admission fields differ')
        admissions.append('__CPROVER_assume('+lower(row['expression']).predicate()+');')
    bounds={}
    for name in ('private_low','private_high','call_private_low','call_private_high'):
        v=lower(d[name]);require(v.sort in {U32,U64},'private bound is not unsigned')
        initializers.append(f'__CPROVER_assert({v.defined},"spx-boundary-private-bound-defined");')
        bounds[name]=v.value
    from .bisimulation_caller_object_runtime import object_call_layout, callback_objects, callback_object_initialization
    records=render_record_transport(d,interface_bundle,lower)
    objects=object_call_layout(d,interface_bundle,source_services,lower)
    require(records is None or objects is not None,'record calls require explicit object footprints')
    # Use actual service invocations as the only source of fresh outcomes. Shared
    # values are indexed by trace position, so repeated services remain independent.
    callback_names={identity:f'spx_boundary_service_{i}' for i,identity in enumerate(ids)}
    native_callback_names=dict(callback_names)
    callbacks=[];target_initializers=[]
    for i,row in enumerate(services):
        require(set(row)-{'result_view','result_value','objects','terminal_services','captured_target_projection','target_sampling','returned_view'}=={'id','arguments','fault','normal_excludes','before','count_diagnostic','maximum_calls'}
                and ('result_view' in row)==('result_value' in row),'service fields differ')
        if 'returned_view' in row:
            require('result_view' not in row and row['fault']=='none' and not row.get('terminal_services'),
                    'returned view requires a normal call without another result rule')
        terminal_services=row.get('terminal_services',[])
        require(isinstance(terminal_services,list) and len(terminal_services)<=32
                and ('terminal_services' not in row or bool(terminal_services))
                and all(isinstance(service,dict) and service.get('disposition')=='terminates'
                        and service.get('status')=='unverified' for service in terminal_services),
                'terminal outcomes need checked supplier premises')
        require(type(row['arguments']) is int and 0<=row['arguments']<=32 and row['fault'] in {'none','uint32-max'},'unsupported service ABI')
        require(type(row['maximum_calls']) is int and 1<=row['maximum_calls']<=d['call_capacity'],'invalid per-service call bound')
        require(isinstance(row['normal_excludes'],list) and all(type(v) is int and 0<=v<2**32 for v in row['normal_excludes']),
                'invalid excluded normal results')
        args=[f'a{j}' for j in range(row['arguments'])]
        local_arguments=objects is not None and bool(objects['orders'][i])
        extra=',struct spx_paired_object *local_objects,uint32_t local_count' if local_arguments else ''
        before={**parameters,'side':ScalarBinding(U32,'e->side'),'events':ScalarBinding(U32,'e->world->count'),
                **{f'calls.{identity}':ScalarBinding(U32,f'e->counts[{j}]') for j,identity in enumerate(ids)}}
        callbacks.append(f'static uint32_t {callback_names[row["id"]]}(struct environment *e'+
                         ''.join(',uint32_t '+arg for arg in args)+extra+'){')
        callbacks.append('__CPROVER_assert(e->side<=1U,"spx-boundary-proof-side");')
        if returned_views:callbacks.append('spx_returned_begin(e->side);')
        callbacks.append(f'__CPROVER_assert(e->counts[{i}]<{row["maximum_calls"]}U,{json.dumps(row["count_diagnostic"])});')
        callbacks.append(_assertions(row['before'],before,{}))
        callbacks.append(f'e->counts[{i}]++;uint32_t args[{max(1,len(args))}]={{'+(','.join(args) or '0U')+'};')
        callbacks.append('uint32_t candidate_value,candidate_fault;')
        if terminal_outcomes: callbacks.append('uint32_t candidate_terminal;')
        callbacks.append('if(e->side==0U){')
        callbacks.append('__CPROVER_assume(candidate_fault<=1U);' if row['fault']=='uint32-max' else 'candidate_fault=0U;')
        if terminal_outcomes:
            callbacks.append(f'__CPROVER_assume(candidate_terminal<={len(terminal_services)}U);')
            callbacks.append('__CPROVER_assume(!candidate_fault || !candidate_terminal);')
        if 'result_value' in row:
            require(row['fault']=='none','borrowed result requires a normal-only supplier')
            fixed=lower(row['result_value'])
            require(fixed.sort==U32,'borrowed native result must be unsigned')
            callbacks.append(f'__CPROVER_assert({fixed.defined},"spx-borrowed-native-result-defined");candidate_value={fixed.value};')
        if 'returned_view' in row:
            callbacks.extend(returned_view_candidate(row['returned_view'],lower))
        for excluded in row['normal_excludes']:callbacks.append(f'__CPROVER_assume(candidate_value!={excluded}U);')
        callbacks.append('}')
        if code_targets:
            callbacks.append('uint32_t invocation_target=0U;')
            if 'captured_target_projection' in row:
                projection=target_projection(row['captured_target_projection'])
                sampling=row.get('target_sampling','service_call')
                target_initializers.extend(entry_target_lines(projection,sampling=sampling,index=i,image_base=d['image_base']))
                callbacks.append('if(e->side==0U)invocation_target=e->native_target;else{')
                callbacks.extend(source_target_lines(projection,index=i,image_base=d['image_base'],sampling=sampling))
                callbacks.extend(['invocation_target=source_target;',
                    '__CPROVER_assert(invocation_target!=0U,"spx-source-captured-target-nonnull");','}'])
        if objects:
            call_parameters={**entry_parameters,**{f'argument_{j}':ScalarBinding(U32,a) for j,a in enumerate(args)}}
            call_machines={key:ScalarBinding(binding.sort,binding.expression.replace('initial.','spx_caller_entry.'))
                           for key,binding in machines.items()}
            callbacks.extend(callback_objects(objects,i,row,lower=lambda raw:lower_call_relation(
                raw,parameters=call_parameters,machines=call_machines)))
        object_arguments=f',objects,{len(row["objects"])}U' if objects else ''
        if records:callbacks.append('if(e->side==1U){spx_record_frame();spx_record_begin_service();}')
        callbacks.append(f'struct spx_paired_outcome outcome=spx_paired_invoke(&calls,e->world,e->side,{i}U,args,{len(args)}U,'+
                         ('invocation_target,' if code_targets else '')+
                         '(struct spx_paired_outcome){candidate_value,candidate_fault'+
                         (',candidate_terminal' if terminal_outcomes else '')+'}'+object_arguments+');')
        if records:
            callbacks.append('if(e->side==1U){')
            if row['id'] in records.identity_results:
                callbacks.append(f'spx_record_return_{_c(records.identity_results[row["id"]])}(outcome.value);')
            callbacks.append('spx_record_end_service();}')
        if objects:callbacks.extend(callback_object_initialization(row,terminal_outcomes=terminal_outcomes))
        if 'returned_view' in row:
            span=row['returned_view']
            callbacks.append(f'spx_returned_grant(e->side,outcome.value,UINT64_C({span["extent"]}),{span["permissions"]}U);')
        callbacks.append(f'e->last_fault=outcome.fault;e->faults[{i}]=outcome.fault;e->results[{i}]=outcome.value;')
        if terminal_outcomes:
            callbacks.append('e->last_terminal=outcome.terminal;')
            callbacks.append('if(e->side==1U && outcome.terminal)spx_caller_terminal_stop();')
        callbacks.append('return outcome.fault?UINT32_MAX:outcome.value;' if row['fault']=='uint32-max' else 'return outcome.value;')
        callbacks.append('}')
        if local_arguments:
            wrapper=callback_names[row['id']]+'_native';native_callback_names[row['id']]=wrapper
            callbacks.extend([f'static uint32_t {wrapper}(struct environment *e,'+
                ','.join('uint32_t '+arg for arg in args)+'){',
                f'return {callback_names[row["id"]]}(e,'+','.join(args)+',0,0U);','}'])
    adapters,source_callbacks=source_service_adapters(interface_bundle,d['operation'],source_services,callbacks=callback_names,
        result_views={row['id']:row['result_view'] for row in services if 'result_view' in row},
        local_views=objects['bindings'] if objects else None,returned_views=returned_views,records=records,
        local_records=objects['record_bindings'] if objects else None)
    view_setup=[];public_spans=[];arguments={}
    for i,(view_name,value_parameter) in enumerate(view_parameters):
        row=view_rows[view_name]
        require(set(row)=={'id','address','extent'},'view definition fields differ')
        address,extent=lower(row['address']),lower(row['extent'])
        require(address.sort==U32 and extent.sort in {U32,U64},'view address/extent sort differs')
        if value_parameter.extent['kind']=='fixed':
            view_setup.append(f'__CPROVER_assert((uint64_t)({extent.value})=={value_parameter.extent["bytes"]}U,"spx-source-fixed-view-extent");')
        permission={'read':1,'write':2,'read_write':3}.get(value_parameter.access)
        require(permission is not None,'unsupported view access')
        view_setup.extend([f'__CPROVER_assert({address.defined} && {extent.defined},"spx-boundary-view-defined");',
            f'uint32_t view_address_{i}={address.value};uint64_t view_extent_{i}={extent.value};',
            f'struct spx_mutable_domain domain_{i}={{&right,view_address_{i},view_extent_{i},{permission}U}};',
            f'spx_runtime view_rt_{i}={{.context=&domain_{i},.read=spx_mutable_read,.write=spx_mutable_write}};',
            f'spx_component_view_context view_context_{i}={{&view_rt_{i},view_address_{i},view_extent_{i},{permission}U}};',
            f'env_right.views[{i}]=(spx_view_v5){{.base={{1U,{i+1}U,1U,0U,view_extent_{i},{permission}U}},'
            f'.extent=view_extent_{i},.element_width=1U,.context=&view_context_{i},.access_context=&view_context_{i},'
            '.read_u8=spx_component_view_read,.write_u8=spx_component_view_write,.read=spx_component_view_read_span,.write=spx_component_view_write_span};',
            f'expected_views[{i}]=env_right.views[{i}];',
            f'view_storage[{i}]=(struct spx_caller_view_storage){{&view_context_{i},&view_rt_{i},&domain_{i},'
            f'view_address_{i},view_extent_{i},{permission}U}};'])
        if view_name in {v.identity for v in signature.parameters}:
            arguments[value_parameter.identity]=f'&env_right.views[{i}]'
        public_spans.append(f'spx_caller_public_span(&m.memory,view_address_{i},view_extent_{i});')
    for p in signature.parameters:
        if p.interpretation!='view':
            require(p.identity in parameters and parameters[p.identity].sort==U32,'source scalar binding is absent')
            if p.type_id in record_types:
                arguments[p.identity]=records.decode(p.type_id,parameters[p.identity].expression)
                if not p.nullable:
                    view_setup.append(f'__CPROVER_assert({parameters[p.identity].expression}!=0U,"spx-source-record-parameter-nonnull");')
            else:arguments[p.identity]=parameters[p.identity].expression
    invocation,source_frame=source_operation_invocation(interface_bundle,d['operation'],symbol,arguments=arguments,
        callbacks=source_callbacks,result_name='source_result',diagnostic=d['context_diagnostic'],observe_frame=terminal_outcomes,records=records)
    post_parameters=dict(entry_parameters)
    for side,env,world in [('left','env_left','left'),('right','env_right','right')]:
        post_parameters[side+'.events']=ScalarBinding(U32,world+'.count')
        for i,identity in enumerate(ids):
            for logical,member in [('calls','counts'),('fault','faults'),('result','results')]:
                post_parameters[f'{side}.{logical}.{identity}']=ScalarBinding(U32,f'{env}.{member}[{i}]')
        for i in range(d['event_capacity']):
            for member in ('address','value','service','position','extent'):
                post_parameters[f'{side}.event.{i}.{member}']=ScalarBinding(U64 if member=='extent' else U32,f'{world}.events[{i}].{member}')
    post_parameters['private_writes']=ScalarBinding(U32,'m.memory.private_writes')
    for index,slot in enumerate(memory):
        if slot['storage']=='private':
            post_parameters['private.'+slot['id']]=ScalarBinding(U32,
                f'spx_caller_private_value(&m.memory,m.memory.slots[{index}].address,{slot["width"]}U)')
    result=signature.results[0] if signature.results else None
    result_type=interface_bundle.intent.schema.type_index[result.type_id] if result else None
    if result is None:
        require('result_view' not in d,'void operation cannot declare a result view')
    elif result.interpretation=='view':
        require(d.get('result_view') in view_rows,'operation result needs a checked existing view mapping')
        index=next(i for i,(name,_) in enumerate(view_parameters) if name==d['result_view'])
        provided=view_parameters[index][1].to_payload();expected=result.to_payload()
        require({**provided,'id':expected['id']}==expected and expected['extent']['kind']=='fixed',
                'operation result view contract differs')
        source_frame+=f'__CPROVER_assert(spx_caller_same_view(&source_result,&expected_views[{index}]),"spx-source-operation-result-view");\n'
        post_parameters['result']=ViewBinding(RelationSortV1('view',type_id=result.type_id),
            f'view_address_{index}',f'view_extent_{index}','')
    elif result_type.kind=='opaque' and result.type_id in record_types:
        if not result.nullable:
            source_frame+='__CPROVER_assert(source_result!=0,"spx-source-record-return-nonnull");\n'
        post_parameters['result']=ScalarBinding(U32,records.encode(result.type_id,'source_result'))
    elif result_type.kind=='record':
        for member in result_type.body['fields']:
            t=interface_bundle.intent.schema.type_index[member['type_id']]
            require(t.kind=='integer' and t.body=={'signed':False,'width_bits':32},'unsupported result observation')
            post_parameters['result.'+member['id']]=ScalarBinding(U32,'source_result.'+_c(member['id']))
    else:
        require(result_type.kind=='integer' and result_type.body=={'signed':False,'width_bits':32},'unsupported scalar result observation')
        post_parameters['result']=ScalarBinding(U32,'source_result')
    post_machines={**machines,**{MachinePlaceV1.parse(field(n).attributes['place']).key:ScalarBinding(U32,'state.'+n)
                                 for n in ('eax','ebx','ecx','edx','esi','edi','esp','ebp','fs_base')}}
    observations=[_assertions(d['assertions'],post_parameters,post_machines),'uint32_t matched_outcomes=0U;']
    require(isinstance(d['outcomes'],list) and 1<=len(d['outcomes'])<=16,'invalid outcome partition')
    for row in d['outcomes']:
        require(set(row)=={'id','guard','exit','assertions'},'outcome fields differ')
        guard=lower_call_relation(row['guard'],parameters=post_parameters,machines=post_machines)
        require(guard.sort==BOOL_SORT,'outcome guard is not Boolean')
        exit=row['exit']
        if exit.get('kind')=='return':
            require(set(exit)=={'kind','value','stack_delta','diagnostic'} and type(exit['stack_delta']) is int
                    and 0<=exit['stack_delta']<=65539,'invalid complete return observation')
            target=lower_call_relation(exit['value'],parameters=post_parameters,machines=post_machines)
            require(target.sort==U32,'return target must be an unsigned word')
            condition=f'{target.defined} && step.kind==SPX_RETURN && step.value=={target.value} && state.esp==initial.esp+{exit["stack_delta"]}U'
        else:
            require(set(exit)=={'kind','rva','diagnostic'} and exit['kind'] in {'fallthrough','memory-fault'},'unsupported original exit')
            require((exit['kind']=='memory-fault' and exit['rva'] is None) or
                    (type(exit['rva']) is int and 0<=exit['rva']<2**32),'invalid exit target')
            condition='step.kind=='+('SPX_FALLTHROUGH' if exit['kind']=='fallthrough' else 'SPX_MEMORY_FAULT')
            if exit['rva'] is not None:condition+=f' && step.target_rva=={exit["rva"]}U'
        observations.extend([f'__CPROVER_assert({guard.defined},"spx-boundary-outcome-defined");',f'if({guard.value}){{matched_outcomes++;',
            f'__CPROVER_assert({condition},{json.dumps(exit["diagnostic"])});',_assertions(row['assertions'],post_parameters,post_machines),'}'])
    observations.extend(['__CPROVER_assert(matched_outcomes==1U,"spx-boundary-outcome-partition");',
        f'if((uint64_t)probe<({bounds["private_low"]}) || (uint64_t)probe>=({bounds["private_high"]}))',
        f'__CPROVER_assert(original_byte(probe)==source_byte(probe),{json.dumps(d["memory_diagnostic"])});'])
    dispatch=render_native_calls(native_calls,native_memory=memory,
        callbacks={identity:(native_callback_names[identity],'m->env->last_fault')+
                   (('m->env->last_terminal',) if terminal_outcomes else ()) for identity in ids},
        parameters={**parameters,'call_memory':memory_parameters['original_memory'],
                    **{'private_initialized.'+slot['id']:ScalarBinding(U32,f'm->memory.slots[{i}].initialized')
                       for i,slot in enumerate(memory) if slot['storage']=='private'},
                    'private_writes':ScalarBinding(U32,'m->memory.private_writes')})
    setup=native_memory_initialization(memory,instance='m.memory',world='&left',private_low=bounds['private_low'],private_high=bounds['private_high'])
    terminal_declarations=terminal_runtime=[]
    if terminal_outcomes:
        terminal_declarations=['static spx_step_result spx_caller_original_step;',
            'static uint64_t spx_caller_private_low,spx_caller_private_high;',
            'static void spx_caller_terminal_stop(void);']
        terminal_runtime=[source_operation_frame_runtime(interface_bundle,d['operation'],
            callbacks=source_callbacks,diagnostic=d['context_diagnostic'],records=records),
            'static void spx_caller_terminal_stop(void){',
            'spx_paired_finish(&calls);spx_caller_source_frame();',
            '__CPROVER_assert(calls.terminated[1]!=0U && !calls.faulted[1] && spx_caller_original_step.kind==SPX_NONLOCAL,"spx-caller-terminal-outcome");',
            'if((uint64_t)probe<spx_caller_private_low || (uint64_t)probe>=spx_caller_private_high)',
            f'__CPROVER_assert(original_byte(probe)==source_byte(probe),{json.dumps(d["memory_diagnostic"])});',
            '__CPROVER_assume(0);','}']
    runtime=['#include "behavioral-c.h"','#include "portable-component-implementation.h"',
        *(['#include "portable-component-local-bytes.h"'] if objects and objects['bindings'] else []),
        *sparse_mutable_memory_runtime(d['event_capacity'],representation_hooks=records is not None),*paired_call_runtime(d['call_capacity'],argument_capacity=max(1,*(s['arguments'] for s in services)),terminal_outcomes=terminal_outcomes,code_targets=code_targets,
            **({'object_capacity':objects['capacity'],'object_byte_capacity':objects['byte_capacity'],'object_observation_sites':True} if objects else {})),
        *native_memory_runtime(len(memory),private_byte_capacity=private_byte_capacity),*_view_runtime_helpers(need_read=True,need_write=True),spx_portable_reference_runtime_v5_source(),
        'static struct boundary_values {'+' '.join(declarations or ['uint32_t reserved;'])+'} values;',
        'static struct spx_mutable_world left,right;static uint32_t probe;',
        f'struct environment {{uint32_t side,last_fault,counts[{len(ids)}],results[{len(ids)}],faults[{len(ids)}];struct spx_mutable_world *world;spx_view_v5 views[{view_capacity}];'+
            ('uint32_t last_terminal;' if terminal_outcomes else '')+
            ('uint32_t native_target;' if code_targets else '')+
            ('struct spx_caller_memory *memory;' if objects else '')+'};',
        'struct machine {struct environment *env;struct spx_caller_memory memory;const spx_machine_state *entry;};',
        'static struct spx_paired_trace calls;',f'static spx_view_v5 expected_views[{view_capacity}];',
        *(['static spx_machine_state spx_caller_entry;'] if objects and objects['call_time'] else []),
        *([f'static uint32_t captured_entry_targets[{len(ids)}];'] if code_targets else []),
        *source_view_storage_runtime(view_capacity),
        *(objects['declarations'] if objects else []),
        *(records.declarations if records else []),
        'static uint8_t original_byte(uint32_t address){return spx_mutable_byte(&left,address);}',
        'static uint8_t source_byte(uint32_t address){return spx_mutable_byte(&right,address);}',
        *(returned_view_runtime(d['call_capacity']) if returned_views else []),
        *(records.runtime if records else []),
        *terminal_declarations,*callbacks,adapters,*terminal_runtime,
        'static uint32_t read_machine(void *opaque,uint32_t address,uint32_t width,uint32_t *fault){struct machine *m=opaque;'+
        ('if(spx_returned_native_access(address,width,1U)){uint32_t value=0U;for(uint32_t i=0U;i<width;i++)value|=(uint32_t)spx_mutable_byte(&left,address+i)<<(8U*i);*fault=0U;return value;}' if returned_views else '')+
        ('if(spx_record_native_access(address,width,1U)){uint32_t value=0U;for(uint32_t i=0U;i<width;i++)value|=(uint32_t)spx_mutable_byte(&left,address+i)<<(8U*i);*fault=0U;return value;}' if records else '')+
        'return spx_caller_read(&m->memory,address,width,fault);}',
        'static void write_machine(void *opaque,uint32_t address,uint32_t width,uint32_t value,uint32_t *fault){struct machine *m=opaque;'+
        ('if(spx_returned_native_access(address,width,2U)){spx_mutable_event(&left,address,width,value,0U,0U);*fault=0U;return;}' if returned_views else '')+
        ('if(spx_record_native_access(address,width,2U)){spx_mutable_event(&left,address,width,value,0U,0U);*fault=0U;return;}' if records else '')+
        'spx_caller_write(&m->memory,address,width,value,fault);}',dispatch,
        f'void {_c(d["proof_entry"])}(void){{',
        'spx_machine_state initial,state;struct boundary_values arbitrary_values;values=arbitrary_values;',
        'uint32_t arbitrary_probe,arbitrary_call_probe;probe=arbitrary_probe;calls.probe=arbitrary_call_probe;',
        *initializers,*admissions,
        *(['spx_caller_entry=initial;'] if objects and objects['call_time'] else []),
        'struct environment env_left={.side=0U,.world=&left},env_right={.side=1U,.world=&right};',
        *view_setup,*(objects['initializers'] if objects else []),'struct machine m={.env=&env_left,.entry=&initial};',setup,*public_spans,
        *(records.initializers if records else []),*(records.spans if records else []),
        *(['right.read_representation=spx_record_read;right.write_representation=spx_record_apply;'] if records else []),
        *target_initializers,
        *(['env_left.memory=&m.memory;'] if objects else []),
        f'spx_runtime rt={{.context=&m,.read=read_machine,.write=write_machine,.image_base={d["image_base"]}U}};',
        f'calls.private_low={bounds["call_private_low"]};calls.private_high={bounds["call_private_high"]};',
        f'state=initial;spx_step_result step=spx_sub_{d["entry"]:08x}(&rt,&state,{d["entry"]}U);',
        *([f'spx_caller_original_step=step;spx_caller_private_low={bounds["private_low"]};spx_caller_private_high={bounds["private_high"]};'] if terminal_outcomes else []),
        'spx_paired_begin_source(&calls);',invocation,'spx_paired_finish(&calls);',source_frame,
        *(['__CPROVER_assert(calls.terminated[0]==0U && calls.terminated[1]==0U,"spx-caller-normal-outcome");'] if terminal_outcomes else []),
        *observations,'}']
    # A separate SAT witness prevents a contradictory definition from proving
    # correctness vacuously. The evidence reader checks this expected failure
    # separately; it is never part of the all-properties-success caller query.
    runtime.extend([f'void {ADMISSION_ENTRY}(void){{',
        'spx_machine_state initial;struct boundary_values arbitrary_values;values=arbitrary_values;',
        *initializers,*admissions,f'__CPROVER_assert(0U,"{ADMISSION_WITNESS}");','}'])
    return '\n'.join(runtime)+'\n'
