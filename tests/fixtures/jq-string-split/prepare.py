"""Define a new boundary first, then attach a native comparison to authored C."""
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


def boundary(network):
    plan,_=load_comparison_package(network)
    if plan['target_id']!='jq' or plan['original']['files'].get('runtime/libjq-1.dll')!=ORIGINAL:
        raise ValueError('requires the reviewed pinned jq path network')
    unit=next(row for row in plan['dependencies'] if row['id']=='string-slice')
    intent=ComponentInterfaceIntentV1.parse(json.loads((network/unit['interface']).read_text()))
    types=[t.to_payload() for t in intent.schema.types if t.kind!='function']
    headers={name:'headers/'+name for name in ('jv.h','jq.h','value-transport.h','value-runtime-impl.h',
        'allocation-observer.h','pe32-entry-hook.h','pe32-import-hook.h')}
    headers.update({name:'dependencies/string-slice/headers/'+name for name in ('string-native.h','COPYING.jq')})
    services,shared=retained_service_inputs(network,component_id='string-slice',
        names=['contents','create','release'],native_symbol='fixture_string_split',
        adapters={name:'adapters/'+name for name in ('value-runtime.c','allocation-observer.c')},headers=headers)
    # Select the reusable constructor contract, with an explicitly reviewed C
    # range adapter instead of importing the slice operation's installation code.
    shared['service_bridge']['adapters']['create']['symbol']='split_create'
    specs={'array':([], 'jv_value','jv_array'),
        'append':([('array','jv_value'),('value','jv_value')],'jv_value','jv_array_append'),
        'codepoint':([('codepoint','u32')],'jv_value','split_codepoint'),
        'empty':([], 'jv_value','split_empty'),
        'valid':([('value','jv_value')],'u32','jv_is_valid')}
    for name,(parameters,result,symbol) in specs.items():
        roles=[dict(root='parameter',value=n,fields=[],transition='borrow_shared' if name=='valid' else 'consume',
            kind='jq-reference',domain='libjq') for n,t in parameters if t=='jv_value']
        if result=='jv_value':
            roles.append(dict(root='result',value='result',fields=[],transition='produce',kind='jq-reference',domain='libjq'))
        services[name]=ServiceDefinition.create(identity='jq.string-split.'+name,types=types,
            parameters=parameters,result=result,resources=roles,effects=['jq.string-split.'+name],outcomes=['return'],
            nonlocal_outcomes=[] if name=='valid' else ['nomem'],
            unobserved=['Lower allocator/reference behavior remains an executable premise; allocation failure is unobserved in this handoff.'])
        shared['service_bridge']['adapters'][name]=dict(symbol=symbol,kind='native',outcomes={'return':None})
    interface=component_interface(component_id='string-split',types=types,
        parameters=[('value','jv_value'),('separator','jv_value')],result='jv_value',services=services)
    shared['service_catalog']=service_catalog(services).to_payload()
    return interface,shared


def prepare(network,authored,output):
    started=time.monotonic();interface,shared=boundary(network)
    if json.loads((authored/'interface.json').read_text())!=interface.to_payload():
        raise ValueError('review changed authoring interface and update the comparison boundary before preparing')
    with comparison_preparation(output) as staged:
        bridge=staged/'bridge.c';bridge.write_text('#include "portable-component-implementation.h"\n'
            '#include "split-native.h"\n#include "value-transport.h"\n#include "comparison-service-bridge.h"\n')
        entry=staged/'native-entry.h';entry.write_text(native_entry_header(original=network/'runtime/libjq-1.dll',
            expected_sha256=ORIGINAL,module='libjq-1.dll',entry_rva=0x2bac0,end_rva=0x2bfb5))
        shared['adapter_files'].update({'driver.c':HERE/'driver.c','bridge.c':bridge,'contents.c':HERE/'contents.c'})
        shared['include_files'].update({'split-native.h':HERE/'split-native.h','BOUNDARY.md':HERE/'BOUNDARY.md',
            'native-entry.h':entry,'binary-driver.h':HERE.parent/'jq-value-transport/binary-driver.h'})
        resources=component_resource_checks(interface,consumes=['value','separator'],produces=['result'],
            resource_kind='jq-reference',provider_domain='libjq',service_id='value-transport',
            interaction_contract_id='string-split.reference-transfer',instrumented_sides=['source'],
            unobserved=['Borrowed direct C reads and native heap internals remain observed, not proved.'],
            nonlocal_allowances={'nomem':dict(max_untransferred=4,max_retained=0)})
        prepare_comparison_package(interface_package=authored/'interface.json',target_id='jq',component_id='string-split',
            source_files={name:authored/'source'/name for name in ('component.c','string-view.h')},
            operation_symbols={'run':'lifted_string_split'},original_files=['runtime/libjq-1.dll'],oracle_kind='native-original',
            cases=[dict(id='retained',arguments=[json.dumps([
                ['a,,b,',','],['a\0a','\0'],['a€',''],['abc','xx'],['aaaa','aa'],['',','],['a,,b,',None,True]]),
                'null','batch']),
                dict(id='program',arguments=['map(.[0] as $s | .[1] as $sep | $s | split($sep))',
                    json.dumps([['a,,b,',','],['a€',''],['a\0a','\0'],['',','],['aaaa','aa']]),'program'])],
            observation_fields=['samples','allocation_lifetime'],assumptions=[(HERE/'BOUNDARY.md').read_text()],
            scope='Two consuming live strings, borrowed contents, allocated substrings and an actual interpreter caller.',
            resource_checks=resources,export_adapters=['adapters/bridge.c','adapters/contents.c'],output=staged/'string-split',**shared)
        write_json(staged/'preparation.json',dict(seconds=time.monotonic()-started,services_reused=['contents','create','release'],
            selected_neighbor_bodies=0,new_tool_internals=False,model_seconds=0,solver_seconds=0))
    print(output/'string-split')


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);commands=parser.add_subparsers(dest='command',required=True)
    define=commands.add_parser('boundary');define.add_argument('network',type=Path);define.add_argument('output',type=Path)
    compare=commands.add_parser('comparison');compare.add_argument('network',type=Path)
    compare.add_argument('authored',type=Path);compare.add_argument('output',type=Path)
    args=parser.parse_args()
    if args.command=='boundary':write_json(args.output,boundary(args.network.resolve())[0].to_payload())
    else:prepare(args.network.resolve(),args.authored.resolve(),args.output.resolve())
