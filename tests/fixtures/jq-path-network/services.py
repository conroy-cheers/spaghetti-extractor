"""jq service declarations; common mechanics live in components.service_authoring."""
import copy

from spaghetti_extractor.components.service_authoring import ServiceDefinition, service_resource_roles
from spaghetti_extractor.components.service_c import CTransport

V,U,I='jv_value','u32','i32'
# The declaration names native semantic adapters; transport is derived from roles.
SPECS={
 'copy':([('value',V)],V,'jv_copy'),
 'kind':([('value',V)],U,'jv_get_kind'),
 'valid':([('value',V)],U,'jv_is_valid'),
 'release':([('value',V)],'unit','jv_free'),
 'abandon':([('value',V)],'unit','path_abandon'),
 'length':([('value',V)],U,'jv_array_length'),
 'array_get':([('value',V),('index',I)],V,'jv_array_get'),
 'array_set':([('value',V),('index',I),('item',V)],V,'jv_array_set'),
 'array_slice':([('value',V),('start',I),('end',I)],V,'jv_array_slice'),
 'string_slice':([('value',V),('start',I),('end',I)],V,'jv_string_slice'),
 'object_get':([('value',V),('key',V)],V,'jv_object_get'),
 'object_set':([('value',V),('key',V),('item',V)],V,'jv_object_set'),
 'indexes':([('value',V),('key',V)],V,'jv_array_indexes'),
 'get':([('value',V),('key',V)],V,'path_dispatch_get'),
 'set':([('value',V),('key',V),('item',V)],V,'path_dispatch_set'),
 'null_value':([],V,'jv_null'), 'array':([],V,'jv_array'), 'object':([],V,'jv_object'),
 'error':([('code',U)],V,'path_error'),
 'index_error':([('value',V),('key',V)],V,'path_index_error'),
 'update_error':([('value',V),('key',V),('item',V)],V,'path_update_error'),
 'number':([('value',V)],'f64','jv_number_value'),
 'slice_bounds':([('value',V),('key',V)],'slice_range','path_portable_slice_bounds'),
}
TRANSPORTS={V:CTransport('jv','spx_value_take','spx_value_borrow','spx_value_pack')}


def types(base):
    result=[copy.deepcopy(t) for t in base['schema']['types'] if t['id'] in (V,U,'unit')]
    result.append(dict(id=I,kind='integer',signed=True,width_bits=32))
    result.append(dict(id='f64',kind='float',format='binary64',value_bits=64))
    for name,fields in [('numeric_index',[('index',I),('is_nan',U)]),('slice_range',[('status',V),('start',I),('end',I)])]:
        result.append(dict(id=name,kind='record',nominal_id='jq.'+name,
            fields=[dict(id=n,type_id=t,bit_width=None) for n,t in fields]))
    return result


def library(base, *, nonlocal_allocation=False):
    definitions={};adapters={}
    for name,(params,result,target) in SPECS.items():
        borrowed=name in ('copy','kind','valid','number')
        values=[n for n,t in params if t==V]
        roles=service_resource_roles(params,borrows=values if borrowed else [],consumes=[] if borrowed else values,
            produces=result==V,resource_kind='jq-reference',provider_domain='libjq')
        if result=='slice_range':
            roles.append(dict(root='result',value='result',fields=['status'],transition='produce',kind='jq-reference',domain='libjq'))
        outcomes=({'value':'spx_value_valid','invalid':'path_value_invalid'} if result==V else
                  {'value':'path_range_valid','invalid':'path_range_invalid'} if result=='slice_range' else {'return':None})
        effects=['jq.reference-borrow' if borrowed else 'jq.reference-abandon' if name=='abandon' else 'jq.reference-transfer'] if roles else []
        if name not in ('kind','valid','number','abandon'):effects.append('jq.native-leaf-or-dispatch')
        definitions[name]=ServiceDefinition.create(identity='jq.'+name,types=types(base),parameters=params,result=result,
            resources=roles,effects=effects,outcomes=list(outcomes),
            nonlocal_outcomes=['nomem'] if nonlocal_allocation and name in (
                'array_set','array_slice','string_slice','object_set','indexes','get','set',
                'array','object','error','index_error','update_error','number','slice_bounds') else [],
            unobserved=['native heap contents and allocation generations',
                'allocation failure with no handler or a returning handler; arbitrary callback behavior',
                'complete service semantics beyond sampled comparisons'])
        adapters[name]=dict(symbol=target,kind='portable' if name=='slice_bounds' else 'native',outcomes=outcomes)
    return definitions,adapters
