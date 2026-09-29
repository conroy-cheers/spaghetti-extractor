"""Prepare consuming byte length with a shared body-independent live string view."""
import argparse
from pathlib import Path
import time

from spaghetti_extractor.components.comparison_environment import retained_service_inputs
from spaghetti_extractor.components.comparison_original import native_entry_header
from spaghetti_extractor.components.comparison_package import load_comparison_package, prepare_comparison_package
from spaghetti_extractor.components.resource_authoring import component_resource_checks
from spaghetti_extractor.components.service_authoring import component_interface
from spaghetti_extractor.util import sha256_file, write_json

HERE=Path(__file__).resolve().parent
ASSUMPTIONS=[
    'Complete jv_string_length_bytes at RVA 0x28e32..0x28eac of the pinned PE32 libjq. The source side traps its original body and assertion tail; invalid kinds and corrupt objects are excluded.',
    'Consume one live string reference and return its stored byte length, at most INT32_MAX. Embedded NUL and malformed UTF-8 are admitted. Retained aliases keep their contents and lose one reference.',
    'The shared string-storage.h adapter reads the existing allocation: 32-bit reference/hash/length-flag/capacity words then bytes. Both native DLL and reviewed portable backend use this layout. Contents remain live until release; pointer transport supplies no lifetime proof.',
    'Reuse exact contents/release declarations, live-value transport and allocation observations. The contents adapter must not call the byte-length operation being replaced.',
    'Single-threaded synchronous live-object execution; native constructors, allocator, release and interpreter are retained dependencies. Finite executable evidence only.',
]


def prepare(base,output):
    start=time.monotonic();plan,_=load_comparison_package(base)
    if plan['target_id']!='jq' or plan['original']['files'].get('runtime/libjq-1.dll')!='50d05ffd1f3cdbb5257f2cda429d9b920d95c091bb88a9d8bcdcb08ae9bacb1d':
        raise ValueError('requires the pinned jq comparison runtime')
    services,shared=retained_service_inputs(base,names=['contents','release'],native_symbol='fixture_string_byte_length',
        adapters=['string-services.c','value-runtime.c','allocation-observer.c'],
        headers=['jv.h','jq.h','string-native.h','string-storage.h','value-transport.h','value-runtime-impl.h',
                 'allocation-observer.h','COPYING.jq','pe32-entry-hook.h','pe32-import-hook.h'])
    # Shared live-value/view types belong to the selected services. Only this
    # operation's signed length result needs an additional declaration.
    boundary=component_interface(component_id='string-byte-length',
        types=[dict(id='i32',kind='integer',width_bits=32,signed=True)],
        parameters=[('value','jv_value')],result='i32',services=services)
    resources=component_resource_checks(boundary,consumes=['value'],produces=[],
        resource_kind='jq-reference',provider_domain='libjq',service_id='value-transport',
        interaction_contract_id='string-byte-length.reference-transfer',instrumented_sides=['source'],
        binding_ids={'parameter.value':'value'},
        unobserved=['Native internals and direct borrowed byte reads are observed by the C consumer, not proved by token instrumentation.'])
    output.mkdir(parents=True,exist_ok=False)
    bridge=output/'bridge.c';bridge.write_text('#include "portable-component-implementation.h"\n#include "string-native.h"\n#include "value-transport.h"\n#include "comparison-service-bridge.h"\n')
    entry=output/'native-entry.h';entry.write_text(native_entry_header(original=base/'runtime/libjq-1.dll',
        expected_sha256=plan['original']['files']['runtime/libjq-1.dll'],module='libjq-1.dll',
        entry_rva=0x28e32,end_rva=0x28eac))
    shared['adapter_files'].update({'driver.c':HERE/'driver.c','bridge.c':bridge})
    shared['include_files']['BOUNDARY.md']=HERE/'BOUNDARY.md'
    shared['include_files']['native-entry.h']=entry
    prepare_comparison_package(interface_package=boundary,target_id='jq',component_id='string-byte-length',
        source_files={'length.c':HERE/'length.c','string-view.h':base/'source/string-view.h'},
        operation_symbols={'run':'lifted_string_byte_length'},
        original_files=['runtime/libjq-1.dll'],oracle_kind='native-original',
        cases=[dict(id=s.replace(':','-'),arguments=[s]) for s in ('unique','retained','program')],
        observation_fields=['strings','program','allocation_lifetime'],assumptions=ASSUMPTIONS,
        scope='Complete consuming byte length using the shared live string view; direct and actual interpreter callers.',
        resource_checks=resources,export_adapters=['adapters/bridge.c'],output=output/'string-byte-length',**shared)
    write_json(output/'preparation.json',dict(seconds=time.monotonic()-start,new_semantic_tool_internals=False,
        services_reused={name:d.contract.contract_sha256 for name,d in services.items()},
        reused_c_adapters={name:sha256_file(shared['adapter_files'][name]) for name in
            ('string-services.c','value-runtime.c','allocation-observer.c')},
        model_seconds=0,solver_seconds=0,strong_qualification=False))
    print(output/'string-byte-length')


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('base',type=Path);p.add_argument('output',type=Path)
    a=p.parse_args();prepare(a.base.resolve(),a.output.resolve())
