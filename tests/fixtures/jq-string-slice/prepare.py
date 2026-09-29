"""Prepare a complete jq string-slice boundary from retained pinned inputs."""
import argparse
from pathlib import Path
import time
from spaghetti_extractor.components.comparison_environment import native_adapter_headers
from spaghetti_extractor.components.comparison_package import load_comparison_package, prepare_comparison_package
from spaghetti_extractor.components.service_authoring import service_catalog
from spaghetti_extractor.util import write_json
from declarations import definitions, resources

HERE=Path(__file__).resolve().parent
ASSUMPTIONS=[
    'Single-threaded live jq string values; signed 32-bit indices and byte lengths no greater than INT32_MAX. Malformed UTF-8 and embedded NUL are admitted contents; invalid pointers and corrupt allocation headers are excluded.',
    'contents borrows actual backing bytes until the input is released. Shared descriptors and retained aliases refer to the same native allocation; no serialized heap reconstruction or checked lifetime theorem.',
    'The complete native jv_string_slice body at RVA 0x29e0a..0x2a145 is absent on the source side. Lower native string constructors, release, allocator and invalid-message construction remain explicit services.',
    'Indices normalize against native byte length before codepoint traversal. Normal construction precedes release; exhausted-start and malformed-input paths release before constructing the empty/error result. Allocation failure preserves this order and stranded references.',
    'The real registered native nomem callback and longjmp are observed with retained aliases and cleanup allocation counts. Returning handlers, arbitrary reentrancy, concurrency and physical memory exhaustion are outside this comparison.',
    'Generated lifecycle and service observations are runtime checks, not checked summaries or activation authority. Borrowed direct C reads require the declared live-object premise.',
]


def prepare(base,output):
    started=time.monotonic();plan,base_intent=load_comparison_package(base)
    if plan['target_id']!='jq' or plan['original']['files'].get('runtime/libjq-1.dll')!='50d05ffd1f3cdbb5257f2cda429d9b920d95c091bb88a9d8bcdcb08ae9bacb1d':
        raise ValueError('requires the pinned jq PE32 original')
    output.mkdir(parents=True,exist_ok=False);intent,services=definitions(base_intent.to_payload())
    bridge=output/'bridge.c';bridge.write_text('#include "portable-component-implementation.h"\n#include "string-native.h"\n#include "value-transport.h"\n#include "comparison-service-bridge.h"\n')
    transport=HERE.parent/'jq-value-transport';arrays=HERE.parent/'jq-array-storage'
    prepare_comparison_package(interface_package=intent,target_id='jq',component_id='string-slice',
        source_files={'slice.c':HERE/'slice.c','string-view.h':HERE/'string-view.h'},
        operation_symbols={'run':'lifted_string_slice'},
        adapter_files={'driver.c':HERE/'driver.c','bridge.c':bridge,'string-runtime.c':HERE/'runtime.c',
            'value-runtime.c':transport/'value-runtime.c','allocation-observer.c':arrays/'allocation-observer.c'},
        include_files={'jv.h':base/'headers/jv.h','string-native.h':HERE/'string-native.h',
            'string-storage.h':HERE/'string-storage.h',
            'string-view.h':HERE/'string-view.h','BOUNDARY.md':HERE/'BOUNDARY.md',
            'value-transport.h':transport/'value-transport.h','value-runtime-impl.h':transport/'observed-runtime.h',
            'allocation-observer.h':arrays/'allocation-observer.h','COPYING.jq':arrays/'COPYING.jq',
            **native_adapter_headers()},
        runtime_files={Path(p).name:base/p for p in plan['runtime_files']},
        link_files={Path(p).name:base/p for p in plan['link_files']},original_files=['runtime/libjq-1.dll'],
        oracle_kind='native-original',cases=[dict(id=case.replace(':','-'),arguments=[case]) for case in
            ['retained','unique','generated:1','generated:23063','generated:4294967295','nomem-copy','nomem-empty','nomem-invalid']],
        observation_fields=['sequences','allocation_failure','allocation_lifetime'],assumptions=ASSUMPTIONS,
        scope='Complete jq string-slice, borrowed live contents and consuming construction/error/failure outcomes.',
        compiler=Path(plan['tools']['compiler']['path']),runner=Path(plan['tools']['runner']['path']),server=Path(plan['tools']['server']['path']),
        output=output/'string-slice',resource_checks=resources(intent),service_catalog=service_catalog(services).to_payload(),
        service_bridge=dict(native_symbol='fixture_string_slice',
            transports={'jv_value':dict(native_type='jv',take='spx_value_take',borrow='spx_value_borrow',pack='spx_value_pack')},
            adapters={name:dict(symbol='jv_free' if name=='release' else 'string_'+name,kind='native',outcomes={'return':None}) for name in services}),
        export_adapters=['adapters/bridge.c','adapters/string-runtime.c'])
    write_json(output/'preparation.json',dict(seconds=time.monotonic()-started,base=str(base),cases=8,
        tooling_gaps=['Resource instrumentation required lifecycle roles for plain numeric parameters; shared validation now permits their omission.'],
        new_proof_rules=False,model_seconds=0,solver_seconds=0,pilot_rebuilds=0,strong_qualification=False))
    print(output/'string-slice')


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('base',type=Path);p.add_argument('output',type=Path)
    a=p.parse_args();prepare(a.base.resolve(),a.output.resolve())
