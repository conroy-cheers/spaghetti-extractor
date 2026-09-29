"""Define a new consuming jq string operation using existing services and C adapters."""
import argparse
from pathlib import Path
import time

from spaghetti_extractor.components.comparison_environment import native_adapter_headers
from spaghetti_extractor.components.comparison_original import native_entry_header
from spaghetti_extractor.components.comparison_package import load_comparison_package, prepare_comparison_package, retained_comparison_environment
from spaghetti_extractor.components.resource_authoring import component_resource_checks
from spaghetti_extractor.components.service_authoring import component_interface, service_catalog, services_from_interface
from spaghetti_extractor.util import sha256_file, write_json

HERE=Path(__file__).resolve().parent
ASSUMPTIONS=[
    'Complete jv_string_length_codepoints at RVA 0x28eac..0x28fc3 of the pinned PE32 libjq. The source-side entry hook traps the complete original body, including the assertion tail. Invalid value kinds and corrupt headers/pointers are outside the boundary.',
    'Consume one live jq string reference, borrow existing bytes until release, and return signed 32-bit decoder-step count. Byte length is at most INT32_MAX; retained aliases observe unchanged contents and one reference release.',
    'Embedded NUL, isolated continuation bytes, overlong encodings, surrogate/out-of-range encodings and incomplete sequences are admitted contents. Each native decoder advance counts once, even when it reports an invalid codepoint. A truncated sequence consumes the remaining span before checking continuation bytes.',
    'Reuse the exact contents/release service declarations, native string view, value transport and string adapters from the existing string-slice/source-backend work. Direct C reads depend on the documented live-object premise; pointer conversion is not a heap/lifetime proof.',
    'Single-threaded synchronous operation with no allocation in the authored loop. Original constructors, interpreter, byte-length service and release remain retained dependencies. Generated ownership observations and original-versus-source cases are finite evidence only.',
]


def prepare(base,output):
    start=time.monotonic();plan,intent=load_comparison_package(base)
    if plan['target_id']!='jq' or plan['original']['files'].get('runtime/libjq-1.dll')!='50d05ffd1f3cdbb5257f2cda429d9b920d95c091bb88a9d8bcdcb08ae9bacb1d':
        raise ValueError('requires the pinned jq comparison runtime')
    services=services_from_interface(intent,plan['service_catalog'],names=['contents','release'])
    types=[t.to_payload() for t in intent.schema.types if t.kind!='function']
    boundary=component_interface(component_id='string-length',types=types,
        parameters=[('value','jv_value')],result='i32',services=services)
    resources=component_resource_checks(boundary,consumes=['value'],produces=[],
        resource_kind='jq-reference',provider_domain='libjq',service_id='value-transport',
        interaction_contract_id='string-length.reference-transfer',instrumented_sides=['source'],
        binding_ids={'parameter.value':'value'},
        unobserved=['Native internals and direct borrowed byte reads are observed by the C consumer, not proved by token instrumentation.'])
    output.mkdir(parents=True,exist_ok=False)
    bridge=output/'bridge.c';bridge.write_text('#include "portable-component-implementation.h"\n#include "string-native.h"\n#include "value-transport.h"\n#include "comparison-service-bridge.h"\n')
    entry=output/'native-entry.h';entry.write_text(native_entry_header(original=base/'runtime/libjq-1.dll',
        expected_sha256=plan['original']['files']['runtime/libjq-1.dll'],module='libjq-1.dll',
        entry_rva=0x28eac,end_rva=0x28fc3))
    transport=HERE.parent/'jq-value-transport';strings=HERE.parent/'jq-string-slice';arrays=HERE.parent/'jq-array-storage'
    prepare_comparison_package(interface_package=boundary,target_id='jq',component_id='string-length',
        source_files={'length.c':HERE/'length.c','string-view.h':strings/'string-view.h'},
        operation_symbols={'run':'lifted_string_length'},
        adapter_files={'driver.c':HERE/'driver.c','bridge.c':bridge,
            'string-services.c':HERE.parent/'jq-portable/string.c','value-runtime.c':transport/'value-runtime.c',
            'allocation-observer.c':arrays/'allocation-observer.c'},
        include_files={'jv.h':base/'headers/jv.h','jq.h':HERE.parent/'jq-path-network/jq.h',
            'string-native.h':strings/'string-native.h','string-storage.h':strings/'string-storage.h','BOUNDARY.md':HERE/'BOUNDARY.md',
            'value-transport.h':transport/'value-transport.h','value-runtime-impl.h':transport/'observed-runtime.h',
            'allocation-observer.h':arrays/'allocation-observer.h','COPYING.jq':arrays/'COPYING.jq',
            'native-entry.h':entry,**native_adapter_headers()},
        original_files=['runtime/libjq-1.dll'],oracle_kind='native-original',
        cases=[dict(id=s.replace(':','-'),arguments=[s]) for s in ('unique','retained','generated:1','generated:23063','generated:4294967295','program')],
        observation_fields=['sequences','program','allocation_lifetime'],assumptions=ASSUMPTIONS,
        scope='Complete consuming codepoint length using borrowed live string bytes; direct and actual interpreter callers.',
        resource_checks=resources,service_catalog=service_catalog(services).to_payload(),
        service_bridge=dict(native_symbol='fixture_string_length',
            transports={'jv_value':dict(native_type='jv',take='spx_value_take',borrow='spx_value_borrow',pack='spx_value_pack')},
            adapters={name:dict(symbol='jv_free' if name=='release' else 'string_contents',kind='native',outcomes={'return':None}) for name in services}),
        export_adapters=['adapters/bridge.c'],output=output/'string-length',**retained_comparison_environment(base))
    write_json(output/'preparation.json',dict(seconds=time.monotonic()-start,new_semantic_tool_internals=False,
        services_reused={name:d.contract.contract_sha256 for name,d in services.items()},
        reused_c_adapters={str(p.relative_to(HERE.parent)):sha256_file(p) for p in
            (HERE.parent/'jq-portable/string.c',transport/'value-runtime.c',arrays/'allocation-observer.c')},
        model_seconds=0,solver_seconds=0,strong_qualification=False))
    print(output/'string-length')


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('base',type=Path);p.add_argument('output',type=Path)
    a=p.parse_args();prepare(a.base.resolve(),a.output.resolve())
