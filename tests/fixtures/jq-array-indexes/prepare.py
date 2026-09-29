"""Define the path getter's retained array-search dependency using shared services."""
import argparse
import json
from pathlib import Path
import time

from spaghetti_extractor.components.comparison_environment import retained_service_inputs
from spaghetti_extractor.components.comparison_original import native_entry_header
from spaghetti_extractor.components.comparison_package import comparison_preparation, load_comparison_package, prepare_comparison_package
from spaghetti_extractor.components.interface_package_v5 import ComponentInterfaceIntentV1
from spaghetti_extractor.components.resource_authoring import component_resource_checks
from spaghetti_extractor.components.service_authoring import ServiceDefinition, component_interface, service_catalog
from spaghetti_extractor.util import write_json

HERE=Path(__file__).resolve().parent
ORIGINAL='50d05ffd1f3cdbb5257f2cda429d9b920d95c091bb88a9d8bcdcb08ae9bacb1d'


def prepare(network,output):
    start=time.monotonic();plan,_=load_comparison_package(network)
    if plan['target_id']!='jq' or plan['original']['files'].get('runtime/libjq-1.dll')!=ORIGINAL:
        raise ValueError('requires the pinned jq path network')
    unit=next(u for u in plan['dependencies'] if u['id']=='value-get')
    intent=ComponentInterfaceIntentV1.parse(json.loads((network/unit['interface']).read_text()))
    types=[t.to_payload() for t in intent.schema.types if t.kind!='function']
    names=['copy','length','array_get','release']
    headers={n:'headers/'+n for n in ('jv.h','jq.h','value-transport.h','value-runtime-impl.h',
        'allocation-observer.h','pe32-entry-hook.h','pe32-import-hook.h')}
    headers['COPYING.jq']='dependencies/string-slice/headers/COPYING.jq'
    services,shared=retained_service_inputs(network,component_id='value-get',names=names,
        native_symbol='fixture_array_indexes',
        adapters={n:'adapters/'+n for n in ('value-runtime.c','allocation-observer.c')},headers=headers)
    # Same service declarations, explicitly selected native implementations for
    # this independent local check, without importing the getter/storage bodies.
    for name,symbol in zip(names,['jv_copy','jv_array_length','jv_array_get','jv_free']):
        shared['service_bridge']['adapters'][name]['symbol']=symbol
    specs={'array':([], 'jv_value','jv_array'),
        'append_index':([('array','jv_value'),('index','u32')],'jv_value','array_indexes_append'),
        'equal':([('left','jv_value'),('right','jv_value')],'u32','jv_equal')}
    for name,(parameters,result,symbol) in specs.items():
        roles=[dict(root='parameter',value=n,fields=[],transition='consume',kind='jq-reference',domain='libjq')
               for n,t in parameters if t=='jv_value']
        if result=='jv_value':
            roles.append(dict(root='result',value='result',fields=[],transition='produce',kind='jq-reference',domain='libjq'))
        services[name]=ServiceDefinition.create(identity='jq.array-indexes.'+name,types=types,
            parameters=parameters,result=result,resources=roles,effects=['jq.array-indexes.'+name],outcomes=['return'],
            nonlocal_outcomes=[] if name=='equal' else ['nomem'],
            unobserved=['Native lower-service internals and allocation failure are outside this finite comparison.'])
        shared['service_bridge']['adapters'][name]=dict(symbol=symbol,kind='native',outcomes={'return':None})
    # Reused array-get/copy predicates name these tiny reviewed native tests.
    shared['service_bridge']['adapters']['array_get']['outcomes']={'value':'spx_value_valid','invalid':'array_indexes_invalid'}
    shared['service_bridge']['adapters']['copy']['outcomes']={'value':'spx_value_valid','invalid':'array_indexes_invalid'}
    interface=component_interface(component_id='array-indexes',types=types,
        parameters=[('value','jv_value'),('needle','jv_value')],result='jv_value',services=services)
    resources=component_resource_checks(interface,consumes=['value','needle'],produces=['result'],
        resource_kind='jq-reference',provider_domain='libjq',service_id='value-transport',
        interaction_contract_id='array-indexes.reference-transfer',instrumented_sides=['source'],
        unobserved=['Native heap internals remain observed through retained values and allocation accounting.'],
        nonlocal_allowances={'nomem':dict(max_untransferred=5,max_retained=0)})
    with comparison_preparation(output) as staged:
        bridge=staged/'bridge.c';bridge.write_text('#include "portable-component-implementation.h"\n'
            '#include "array-indexes-native.h"\n#include "value-transport.h"\n'
            '#include "comparison-service-bridge.h"\n')
        entry=staged/'native-entry.h';entry.write_text(native_entry_header(original=network/'runtime/libjq-1.dll',
            expected_sha256=ORIGINAL,module='libjq-1.dll',entry_rva=0x2c226,end_rva=0x2c5e3))
        shared['adapter_files'].update({'driver.c':HERE/'driver.c','bridge.c':bridge})
        shared['include_files'].update({'array-indexes-native.h':HERE/'array-indexes-native.h',
            'BOUNDARY.md':HERE/'BOUNDARY.md','native-entry.h':entry,
            'binary-driver.h':HERE.parent/'jq-value-transport/binary-driver.h'})
        shared['service_catalog']=service_catalog(services).to_payload()
        prepare_comparison_package(interface_package=interface,target_id='jq',component_id='array-indexes',
            source_files={'indexes.c':HERE/'indexes.c'},operation_symbols={'run':'lifted_array_indexes'},
            original_files=['runtime/libjq-1.dll'],oracle_kind='native-original',
            cases=[dict(id='retained',arguments=['[1,2,1,2,3]','[1,2]','retained']),
                   dict(id='aliased',arguments=['[{"x":[1,2]},"a",null]','null','aliased']),
                   dict(id='empty-pattern',arguments=['[1,2]','[]','retained']),
                   dict(id='program',arguments=['[.items[[1,2]],getpath(["items",[1,2]])]',
                        '{"items":[1,2,1,2,3]}','program'])],
            observation_fields=['samples','allocation_lifetime'],
            assumptions=[(HERE/'BOUNDARY.md').read_text()],resource_checks=resources,
            scope='Consuming array subsequence lookup with live shared values and interpreter callers.',
            export_adapters=['adapters/bridge.c'],output=staged/'array-indexes',**shared)
        write_json(staged/'preparation.json',dict(seconds=time.monotonic()-start,new_tool_internals=False,
            services_reused=names,selected_neighbor_bodies=0,model_seconds=0,solver_seconds=0))
    print(output/'array-indexes')


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('network',type=Path);parser.add_argument('output',type=Path)
    args=parser.parse_args();prepare(args.network.resolve(),args.output.resolve())
