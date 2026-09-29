"""Checked native call instantiation over typed relations and supplier facts.

Call definitions are checker inputs derived from validated summaries or explicitly
named runtime contracts. This module grants neither contract availability nor
runtime qualification. Callback C bindings are checker-owned, never public text.
"""

import json

from .bisimulation_call_relations import ScalarBinding, constant as constant, expression, lower_call_relation
from .bisimulation_caller_memory import ENTRY_REGISTERS, U32, checked_native_memory, entry_offset
from .bisimulation_caller_targets import native_target_lines
from .relation_ir import BOOL_SORT, MachinePlaceV1, RelationExpressionV1


SCALAR_FIELDS = {*ENTRY_REGISTERS, 'cf','zf','sf','of','pf','df','eflags',
    'x87_control','x87_status','x87_pending_exception','x87_last_opcode',
    'x87_instruction_pointer','x87_code_selector','x87_data_pointer','x87_data_selector'}
ARRAY_FIELDS = ('x87_stack[continuation_slot].empty', 'x87_stack[continuation_slot].tag',
                'x87_stack[continuation_slot].value_bytes[continuation_byte]')


def require(value, message):
    if not value:raise ValueError('native call: '+message)


def register(name, phase='caller_before'):
    require(name in ENTRY_REGISTERS or name=='df', 'unsupported register projection')
    return RelationExpressionV1.parse({'op':'machine','sort':U32.to_payload(),'args':[],
        'attributes':{'place':{'kind':'flag' if name=='df' else 'register','phase':phase,'width':32,
                             'selector':{'flag' if name=='df' else 'register':name}}}})


def stack_word(offset):
    require(type(offset) is int and 0 <= offset <= 124 and offset%4==0, 'unsupported argument offset')
    return RelationExpressionV1.parse({'op':'machine','sort':U32.to_payload(),'args':[],
        'attributes':{'place':{'kind':'stack','phase':'caller_before','width':32,'selector':{'offset':offset}}}})


def requirement(identity, value):
    return {'id':identity,'expression':value.to_payload()}


def equal(left, right):
    return expression('eq',BOOL_SORT,left,right)


def summary_return(contract):
    """Normalize only reviewed normal-return facts; faults preserve no frame."""
    normal=contract['normal_return'];projection=contract['native_projection']
    require(normal['result']['kind']=='equal-u32', 'unsupported supplier result relation')
    require(normal['frame_quantifiers']=={'continuation_slot':[0,8],'continuation_byte':[0,10]},
            'unsupported physical frame quantifiers')
    known={f'state.{field}==initial.{field}':field for field in (*SCALAR_FIELDS,*ARRAY_FIELDS)}
    raw=normal['preserved_equalities']
    require(isinstance(raw,list) and all(isinstance(v,str) and v in known for v in raw)
            and raw==sorted(set(raw)), 'unsupported normal frame relation')
    delta=projection['normal_call_stack_delta']
    require(all(type(v) is int for v in (delta,projection['call_entry_stack_delta'],normal['stack_delta']))
            and delta==projection['call_entry_stack_delta']+normal['stack_delta'], 'supplier stack transport differs')
    return checked_return({'result_field':normal['result']['native_field'],'stack_delta':delta,
                           'preserved_fields':sorted(known[v] for v in raw)})


def checked_return(value):
    require(isinstance(value,dict) and set(value)=={'result_field','stack_delta','preserved_fields'},
            'normal return fields differ')
    field,delta,preserved=value['result_field'],value['stack_delta'],value['preserved_fields']
    require((field is None or field in set(ENTRY_REGISTERS)-{'esp','fs_base'}) and type(delta) is int and -256<=delta<=256,
            'unsupported result register or stack delta')
    require(isinstance(preserved,list) and all(isinstance(v,str) and v in SCALAR_FIELDS|set(ARRAY_FIELDS) for v in preserved)
            and preserved==sorted(set(preserved)) and field not in preserved and 'esp' not in preserved,
            'conflicting or unsupported normal frame')
    return {'result_field':field,'stack_delta':delta,'preserved_fields':preserved.copy()}


def _event(value):
    fields={'kind','source_rva','instruction_rva','target_rva','return_rva','call_index','argument_count','stack_input_count'}
    require(isinstance(value,dict) and value.get('kind') in {'internal','import','indirect'}, 'unsupported event kind')
    require(set(value)==fields|({'dll','symbol'} if value['kind']=='import' else set()), 'event fields differ')
    require(all(type(value[k]) is int and 0<=value[k]<2**32 for k in fields-{'kind'}), 'invalid event integer')
    if value['kind']=='import':
        require(all(isinstance(value[k],str) and 0<len(value[k])<=256 and all(32<=ord(c)<127 for c in value[k])
                    for k in ('dll','symbol')), 'unsupported import spelling')
    if value['kind']=='indirect':
        require(value['target_rva']==0, 'indirect event target must be supplied by its captured projection')
    return dict(value)


def call_definition(identity, event, arguments, requires, normal_return, *, entry_stack_delta):
    return {'id':identity,'event':_event(event),'arguments':[a.to_payload() for a in arguments],
            'requires':requires,'normal_return':checked_return(normal_return),'entry_stack_delta':entry_stack_delta}


def _machine_bindings():
    return {MachinePlaceV1.parse(register(name,phase).attributes['place']).key:ScalarBinding(U32,prefix+name)
            for phase,prefix in [('entry','m->entry->'),('caller_before','input->')]
            for name in (*ENTRY_REGISTERS,'df')}


def checked_call_sites(definitions, service_ids):
    """One logical service may have several exact native sites, with one ABI.

    Site-local stack transport and applicability are checked at every invocation.
    Repeated execution of one site uses its existing binding; duplicate dispatch
    keys cannot provide alternate guarantees for the same machine event.
    """
    require(isinstance(definitions,list) and 1<=len(definitions)<=32, 'invalid call inventory')
    sites=set();arities={}
    for row in definitions:
        require(isinstance(row,dict) and row.get('id') in service_ids, 'call has no declared service')
        event=_event(row.get('event'));key=(event['kind'],event['source_rva'],event['instruction_rva'])
        require(key not in sites, 'ambiguous native dispatch');sites.add(key)
        arguments=row.get('arguments')
        require(isinstance(arguments,list) and len(arguments)<=32, 'invalid argument inventory')
        arity=arities.setdefault(row['id'],len(arguments))
        require(arity==len(arguments), 'native sites for one service have different argument counts')
    require(set(arities)==set(service_ids), 'native/source service coverage differs')
    return arities


def render_native_calls(definitions, *, native_memory, callbacks, parameters):
    """Callbacks bind a function, fault expression and optional terminal tag.

    A terminal callback has no normal-return register or stack guarantees.
    These expressions are supplied by the checked boundary, never authored C.
    """
    checked_call_sites(definitions,set(callbacks))
    memory=checked_native_memory(native_memory);seen=set()
    lines=['spx_call_status spx_invoke_call(spx_runtime *rt,const spx_call_event *ev,',
           ' const spx_machine_state *input,spx_machine_state *output){',
           ' struct machine *m=rt->context;spx_machine_state arbitrary;*output=arbitrary;']
    for row in definitions:
        indirect=row['event']['kind']=='indirect'
        require(isinstance(row,dict) and set(row)-({'target_sampling'} if indirect else set())=={'id','event','arguments','requires','normal_return','entry_stack_delta'}
                | ({'captured_target_projection'} if indirect else set()),
                'call definition fields differ')
        require(isinstance(row['id'],str) and row['id'] in callbacks, 'call has no checked callback binding')
        event=_event(row['event']);key=(event['kind'],event['source_rva'],event['instruction_rva'])
        require(key not in seen, 'ambiguous native dispatch');seen.add(key)
        delta=row['entry_stack_delta'];require(type(delta) is int and -256<=delta<=256, 'invalid incoming stack delta')
        kind={'internal':'SPX_CALL_INTERNAL_DIRECT','import':'SPX_CALL_EXTERNAL_IMPORT','indirect':'SPX_CALL_INDIRECT'}[event['kind']]
        lines.append(f' if(ev->kind=={kind} && ev->source_rva=={event["source_rva"]}U && ev->instruction_rva=={event["instruction_rva"]}U){{')
        checks=[f'ev->{k}=={event[k]}U' for k in ('target_rva','return_rva','call_index','argument_count','stack_input_count')
                if k!='target_rva' or not indirect]
        if indirect:checks.extend(['ev->dll==0','ev->symbol==0','ev->ordinal==0U','ev->has_ordinal==0U'])
        for field in ('dll','symbol') if event['kind']=='import' else ():
            checks.append(f'ev->{field} && '+' && '.join(f'ev->{field}[{i}]=={ord(c)}' for i,c in enumerate(event[field]+'\0')))
        lines.append('  __CPROVER_assert('+ ' && '.join(checks)+',"spx-native-call-event");')
        if indirect:lines.extend(native_target_lines(row['captured_target_projection'],
            sampling=row.get('target_sampling','service_call'),index=list(callbacks).index(row['id'])))
        lines.append(f'  __CPROVER_assert(input->esp==m->entry->esp {"-" if delta<0 else "+"} {abs(delta)}U,"spx-native-call-entry-stack");')
        require(isinstance(row['arguments'],list) and len(row['arguments'])<=32, 'invalid argument inventory')
        machines=_machine_bindings();bound=dict(parameters)
        for i,raw in enumerate(row['arguments']):
            arg=RelationExpressionV1.parse(raw);require(arg.sort==U32, 'only uint32 native call arguments are implemented')
            if arg.op=='machine' and arg.attributes['place']['kind']=='stack':
                place=MachinePlaceV1.parse(arg.attributes['place']);offset=place.payload.get('offset')
                require(place.to_payload()==MachinePlaceV1.parse(stack_word(offset).attributes['place']).to_payload(), 'unsupported private argument projection')
                target=entry_offset('esp',delta+offset).to_payload()
                index=next((j for j,slot in enumerate(memory) if slot['storage']=='private' and slot['width']==4 and slot['address']==target),None)
                address=f'input->esp+{offset}U'
                if index is None:
                    value=f'spx_caller_private_value(&m->memory,{address},4U)'
                else:
                    # This index is an optimization only. Its binding to the real
                    # ABI location and written contents remains a proof obligation.
                    lines.append(f'  const struct spx_caller_slot *slot_{i}=&m->memory.slots[{index}];')
                    lines.append(f'  __CPROVER_assert(slot_{i}->private_storage && slot_{i}->width==4U && slot_{i}->address==({address}),"spx-native-call-argument-location");')
                    lines.append(f'  __CPROVER_assert(slot_{i}->initialized,"spx-native-call-argument-initialized");')
                    value=f'slot_{i}->value'
                lines.append(f'  uint32_t arg_{i}={value};')
            else:
                lowered=lower_call_relation(arg,parameters=parameters,machines=machines)
                lines.extend([f'  __CPROVER_assert({lowered.defined},"spx-native-call-argument-defined");',
                              f'  uint32_t arg_{i}={lowered.value};'])
            bound['argument_'+str(i)]=ScalarBinding(U32,'arg_'+str(i))
        require(isinstance(row['requires'],list), 'invalid call requirements')
        for check in row['requires']:
            require(isinstance(check,dict) and set(check)=={'id','expression'} and isinstance(check['id'],str), 'invalid named call requirement')
            predicate=lower_call_relation(check['expression'],parameters=bound,machines=machines).predicate()
            lines.append(f'  __CPROVER_assert({predicate},{json.dumps(check["id"])});')
        callback=callbacks[row['id']]
        require(isinstance(callback,tuple) and len(callback) in {2,3}, 'invalid callback binding')
        function,fault=callback[:2]
        args=''.join(',arg_'+str(i) for i in range(len(row['arguments'])))
        lines.extend([f'  uint32_t result={function}(m->env{args});',f'  if({fault})return SPX_CALL_MEMORY_FAULT;'])
        if len(callback)==3:
            lines.append(f'  if({callback[2]})return SPX_CALL_NONLOCAL;')
        normal=checked_return(row['normal_return']);delta=normal['stack_delta']
        lines.extend([f'  output->{normal["result_field"]}=result;' if normal['result_field'] is not None else '  (void)result;',
                      f'  output->esp=input->esp {"-" if delta<0 else "+"} {abs(delta)}U;'])
        for field in normal['preserved_fields']:
            prefix=''
            if field in ARRAY_FIELDS:
                prefix='for(uint32_t continuation_slot=0;continuation_slot<8U;continuation_slot++)'
                if '[continuation_byte]' in field:prefix+='for(uint32_t continuation_byte=0;continuation_byte<10U;continuation_byte++)'
            lines.append(f'  {prefix}output->{field}=input->{field};')
        lines.extend(['  return SPX_CALL_OK;',' }'])
    lines.extend([' __CPROVER_assert(0U,"spx-native-call-covered");return SPX_CALL_MEMORY_FAULT;','}'])
    return '\n'.join(lines)+'\n'
