"""Instantiate checked supplier premises at the actual native invocation.

Caller admission is editable. It never licenses dropping a supplier premise: all
consumed premises below are assertions over the current call frame and memory.
The existing paired runtime subsequently checks corresponding source arguments,
live views and current bytes before coupling outcomes and post-memory.
"""
from copy import deepcopy

from .bisimulation_call_relations import constant, expression, parameter
from .bisimulation_caller_boundary import BYTES, U32, add, all_of, any_of, eq, le, named, sub, wide
from .bisimulation_native_calls import register, stack_word
from .relation_ir import RelationExpressionV1

WITNESSES=('length','length_target','scratch_address','scratch_extent')


def require(value, message):
    if not value:raise ValueError('supplier call: '+message)


def substitute_parameters(raw, replacements):
    """Capture-free typed substitution in the existing relation vocabulary."""
    node=RelationExpressionV1.parse(raw)
    if node.op=='logical':
        path=node.attributes['path']
        require(path['root']=='parameter' and not path['fields'] and path['id'] in replacements,
                'supplier premise parameter is unbound')
        replacement=replacements[path['id']]
        require(replacement.sort==node.sort,'supplier premise binding sort differs')
        return replacement
    payload=node.to_payload()
    payload['args']=[substitute_parameters(arg.to_payload(),replacements).to_payload() for arg in node.arguments]
    return RelationExpressionV1.parse(payload)


def instantiate_borrowed_supplier_call(facts, boundary, native, service, native_memory):
    """Seal a normal borrowed result and check the child's actual entry frame."""
    argument,=facts['signature']['parameters']
    require(native['arguments']==[stack_word(0).to_payload()] and service['views']=={}
            and service['arguments']==[parameter(argument['id'],U32).to_payload()],
            'borrowed supplier scalar projection differs')
    stack=wide(register('esp'));child=sub(stack,constant(4,64));private=facts['private_frame']
    low=sub(child,constant(-private['low'],64));high=add(child,constant(private['high'],64))
    image=facts['image'];base=constant(image['base'],64);end=constant(image['base']+image['size'],64)
    checks=[named('supplier-call-borrowed-private-entry',all_of(
        le(constant(4-private['low'],64),stack),le(high,constant(2**32,64)),
        any_of(le(high,base),le(end,low))))]
    for view in boundary['views']:
        address=wide(RelationExpressionV1.parse(view['address']))
        extent=wide(RelationExpressionV1.parse(view['extent']))
        checks.append(named('supplier-call-borrowed-public-view-'+view['id'],any_of(
            le(add(address,extent),low),le(high,address))))
    # Initialized native slots hold caller continuation data. Future slots may
    # overlap the child's frame: their next write establishes a new value, and
    # reads before that write are rejected by the native memory checker. The
    # initialized flag comes from execution, never a caller-authored assertion.
    for slot in native_memory:
        if slot['storage']!='private':continue
        address=wide(RelationExpressionV1.parse(slot['address']))
        for index,(offset,count) in enumerate([(0,4),*private['writes']]):
            start=sub(child,constant(-offset,64)) if offset<0 else add(child,constant(offset,64))
            checks.append(named(f'supplier-call-live-slot-{slot["id"]}-{index}',any_of(
                eq(parameter('private_initialized.'+slot['id'],U32),constant(0)),
                le(add(address,constant(slot['width'],64)),start),le(add(start,constant(count,64)),address))))
    outer={name:wide(RelationExpressionV1.parse(boundary[name])) for name in
        ('private_low','private_high','call_private_low','call_private_high')}
    checks.append(named('supplier-call-input-private-scope',any_of(
        eq(outer['call_private_low'],outer['call_private_high']),
        all_of(le(low,outer['call_private_low']),le(outer['call_private_high'],high)))))
    checks.append(named('supplier-call-output-private-scope',all_of(
        le(outer['private_low'],low),le(high,outer['private_high']))))
    result=deepcopy(native);result['normal_return']=deepcopy(facts['normal_return'])
    result['requires']=[*result['requires'],*checks]
    return result


def instantiate_supplier_call(facts, boundary, native, service, witnesses):
    """Return a sealed call definition; scalar/view mappings supply no guarantees."""
    require(native['id']==service['id'],'native/source supplier identity differs')
    require(isinstance(witnesses,dict) and set(witnesses)==set(WITNESSES),'supplier witness inventory differs')
    views={row['id']:row for row in boundary['views']}
    required_views={'text',*facts['native_projection']['image_views']}
    require(set(service['views'])==required_views and all(name in views for name in service['views'].values()),
            'supplier view correspondence is incomplete')
    view=lambda name:views[service['views'][name]]
    text=view('text');projection=facts['native_projection']
    text_register=register(projection['text']['register'])
    require(native['arguments']==[text_register.to_payload()], 'native supplier arguments differ from checked projection')
    expected=expression('view_address',U32,parameter('text',BYTES)).to_payload()
    require(service['arguments']==[expected],'source supplier arguments differ from checked projection')
    stack=sub(register('esp'),constant(-projection['call_entry_stack_delta']))
    bindings={name:RelationExpressionV1.parse(witnesses[name]) for name in WITNESSES}
    bindings.update(stack=stack,text_address=text_register,text_extent=RelationExpressionV1.parse(text['extent']),
                    entry_memory=parameter('call_memory',BYTES))
    checks=[named('supplier-call-'+row['id'],substitute_parameters(row['expression'],bindings)) for row in facts['entry_relations']]
    checks.append(named('supplier-call-text-view',eq(text_register,RelationExpressionV1.parse(text['address']))))
    checks.append(named('supplier-call-native-flags',le(register('df'),constant(1))))
    for name,physical in projection['image_views'].items():
        row=view(name)
        checks.append(named('supplier-call-image-view-'+name,all_of(
            eq(RelationExpressionV1.parse(row['address']),constant(physical['address'])),
            eq(wide(RelationExpressionV1.parse(row['extent'])),constant(physical['extent'],64)))))
    private=facts['private_frame'];low=sub(wide(stack),constant(-private['low'],64));high=add(wide(stack),constant(private['high'],64))
    outer={name:wide(RelationExpressionV1.parse(boundary[name])) for name in
           ('private_low','private_high','call_private_low','call_private_high')}
    # The input comparison may omit only callee-private bytes. Post-comparison
    # must not assume that the callee exports equality of its own private frame.
    checks.append(named('supplier-call-input-private-scope',any_of(
        eq(outer['call_private_low'],outer['call_private_high']),
        all_of(le(low,outer['call_private_low']),le(outer['call_private_high'],high)))))
    checks.append(named('supplier-call-output-private-scope',all_of(
        le(outer['private_low'],low),le(high,outer['private_high']))))
    result=deepcopy(native)
    result['normal_return']=deepcopy(facts['normal_return'])
    result['requires']=[*result['requires'],*checks]
    return result
