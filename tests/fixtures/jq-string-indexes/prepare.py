"""Prepare a new two-input string search using the retained live-object services."""
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
ASSUMPTIONS=[
    'Complete jv_string_indexes at RVA 0x28fc3..0x292ff of the pinned PE32 libjq, including both assertion tails. The original body is trapped on the source side; invalid kinds and corrupt allocations are excluded.',
    'Consume one reference for each live string parameter and return an owned array of overlapping match positions. Inputs may share an allocation, with distinct owned references. Other retained aliases preserve their contents.',
    'Byte lengths are at most INT32_MAX. Empty patterns produce no indexes. Embedded NUL and malformed bytes are admitted; the native lead-byte width rule determines positions even for malformed sequences.',
    'Reuse the existing contents/release declarations, shared string view and live-value transport. Array creation, append/number construction and validity are explicit lower services; no search body is hidden in an adapter.',
    'Single-threaded synchronous live objects. Original allocation, reference counting and interpreter remain dependencies. Nonlocal allocation failure is declared but not exercised here; returning handlers, arbitrary reentrancy and concurrency are outside this comparison.',
    'Finite memory, alias, lifetime and interpreter comparisons are experimental evidence, not checked memory summaries or strong qualification.',
]


def prepare(base, output, *, services_component=None):
    with comparison_preparation(output) as staged:
        _prepare(base, staged, services_component=services_component)
    print(output/'string-indexes')


def _prepare(base, output, *, services_component=None):
    start=time.monotonic();plan,intent=load_comparison_package(base)
    if plan['target_id']!='jq' or plan['original']['files'].get('runtime/libjq-1.dll')!='50d05ffd1f3cdbb5257f2cda429d9b920d95c091bb88a9d8bcdcb08ae9bacb1d':
        raise ValueError('requires the pinned jq string comparison runtime')
    if services_component is None:
        services,shared=retained_service_inputs(base,names=['contents','release'],native_symbol='fixture_string_indexes',
            adapters=['string-services.c','value-runtime.c','allocation-observer.c'],
            headers=['jv.h','jq.h','string-native.h','string-storage.h','value-transport.h','value-runtime-impl.h',
                     'allocation-observer.h','COPYING.jq','pe32-entry-hook.h','pe32-import-hook.h'])
        view=base/'source/string-view.h'
    else:
        # Explicitly reviewed path-network inputs; do not infer new adapter C
        # or inherit the selected string operation's body, driver or evidence.
        unit=next((u for u in plan.get('dependencies',[]) if u['id']==services_component),None)
        if unit is None:
            raise ValueError('choose a selected string component from the path network')
        prefix='dependencies/'+services_component+'/'
        intent=ComponentInterfaceIntentV1.parse(json.loads((base/unit['interface']).read_text()))
        headers={name:'headers/'+name for name in ('jv.h','jq.h','value-transport.h','value-runtime-impl.h',
            'allocation-observer.h','pe32-entry-hook.h','pe32-import-hook.h')}
        headers.update({name:prefix+'headers/'+name for name in ('string-native.h','COPYING.jq')})
        services,shared=retained_service_inputs(base,component_id=services_component,
            names=['contents','release'],native_symbol='fixture_string_indexes',
            adapters={name:'adapters/'+name for name in ('value-runtime.c','allocation-observer.c')},headers=headers)
        shared['adapter_files']['string-services.c']=HERE/'network-contents.c'
        view=base/prefix/'source/string-view.h'
    types=[t.to_payload() for t in intent.schema.types if t.kind!='function']
    specs={'array':([], 'jv_value', 'jv_array'),
           'append_index':([('array','jv_value'),('index','u32')], 'jv_value', 'indexes_append'),
           'valid':([('value','jv_value')], 'u32', 'jv_is_valid')}
    for name,(params,result,symbol) in specs.items():
        roles=[dict(root='parameter',value=n,fields=[],transition='borrow_shared' if name=='valid' else 'consume',
                    kind='jq-reference',domain='libjq') for n,t in params if t=='jv_value']
        if result=='jv_value':
            roles.append(dict(root='result',value='result',fields=[],transition='produce',kind='jq-reference',domain='libjq'))
        services[name]=ServiceDefinition.create(identity='jq.string-indexes.'+name,types=types,
            parameters=params,result=result,resources=roles,effects=['jq.string-indexes.'+name],outcomes=['return'],
            nonlocal_outcomes=[] if name=='valid' else ['nomem'],
            unobserved=['Lower allocation and lifetime behavior remain executable service premises; nonlocal failure is not exercised by this handoff.'])
        shared['service_bridge']['adapters'][name]=dict(symbol=symbol,kind='native',outcomes={'return':None})
    boundary=component_interface(component_id='string-indexes',types=types,
        parameters=[('value','jv_value'),('needle','jv_value')],result='jv_value',services=services)
    resources=component_resource_checks(boundary,consumes=['value','needle'],produces=['result'],
        resource_kind='jq-reference',provider_domain='libjq',service_id='value-transport',
        interaction_contract_id='string-indexes.reference-transfer',instrumented_sides=['source'],
        binding_ids={'parameter.value':'value','parameter.needle':'needle','result.result':'result'},
        unobserved=['Native heap internals and borrowed reads are observed by the C consumer, not proved by token instrumentation.'],
        nonlocal_allowances={'nomem':dict(max_untransferred=3,max_retained=0)})
    bridge=output/'bridge.c';bridge.write_text('#include "portable-component-implementation.h"\n#include "indexes-native.h"\n#include "value-transport.h"\n#include "comparison-service-bridge.h"\n')
    entry=output/'native-entry.h';entry.write_text(native_entry_header(original=base/'runtime/libjq-1.dll',
        expected_sha256=plan['original']['files']['runtime/libjq-1.dll'],module='libjq-1.dll',
        entry_rva=0x28fc3,end_rva=0x292ff))
    shared['adapter_files'].update({'driver.c':HERE/'driver.c','bridge.c':bridge})
    shared['include_files'].update({'indexes-native.h':HERE/'indexes-native.h','BOUNDARY.md':HERE/'BOUNDARY.md','native-entry.h':entry})
    shared['service_catalog']=service_catalog(services).to_payload()
    prepare_comparison_package(interface_package=boundary,target_id='jq',component_id='string-indexes',
        source_files={'indexes.c':HERE/'indexes.c','string-view.h':view},
        operation_symbols={'run':'lifted_string_indexes'},original_files=['runtime/libjq-1.dll'],oracle_kind='native-original',
        cases=[dict(id=name,arguments=[name]) for name in ('unique','retained','aliased','program')],
        observation_fields=['searches','program','allocation_lifetime'],assumptions=ASSUMPTIONS,
        scope='Two consuming live strings, borrowed bytes and array results through direct and actual interpreter callers.',
        resource_checks=resources,export_adapters=['adapters/bridge.c'],output=output/'string-indexes',**shared)
    write_json(output/'preparation.json',dict(seconds=time.monotonic()-start,new_tool_internals=False,
        services_component=services_component or plan['component_id'],
        services_reused=['contents','release'],adapters_reused=(['string-services.c'] if services_component is None else [])+
            ['value-runtime.c','allocation-observer.c'],
        contents_adapter='retained standalone adapter' if services_component is None else 'operator-owned network-contents.c',
        new_adapter='indexes-native.h: array append of a numeric position; no state transport change',
        model_seconds=0,solver_seconds=0,strong_qualification=False))


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('base',type=Path);parser.add_argument('output',type=Path)
    parser.add_argument('--services-component',help='reuse the named string component in a reviewed path-network workspace')
    args=parser.parse_args();prepare(args.base.resolve(),args.output.resolve(),services_component=args.services_component)
