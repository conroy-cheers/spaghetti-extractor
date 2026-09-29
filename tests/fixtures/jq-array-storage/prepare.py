"""Prepare connected array components from retained jq inputs, without pilot builds."""
import argparse
from pathlib import Path
import time

from spaghetti_extractor.components.comparison_composition import bind_dependencies
from spaghetti_extractor.components.comparison_environment import native_adapter_headers
from spaghetti_extractor.components.comparison_package import load_comparison_package, prepare_comparison_package
from spaghetti_extractor.components.service_authoring import component_interface, service_catalog
from spaghetti_extractor.util import sha256_file, write_json
from declarations import definitions, SPECS, TYPES, UNITS

HERE=Path(__file__).resolve().parent
ORIGINAL='50d05ffd1f3cdbb5257f2cda429d9b920d95c091bb88a9d8bcdcb08ae9bacb1d'
ASSUMPTIONS=[
    'Single-threaded live well-formed jq descriptors and array backing objects, with native-layout aliases preserved.',
    'Allocation byte spans do not wrap PE32 size_t; invalid objects and overflowing allocations are outside the represented domain.',
    'C adapters preserve all descriptor fields and the pinned native array layout; no checked heap relation is claimed.',
    'The native guarded allocator and non-array destruction/error services remain dependencies; foreign destructors can still release nested arrays natively.',
    'Finite returned-content, retained-alias, reference-count and CRT-allocation observations through cleanup; diagnostic serialization allocations are excluded from counts.',
    'Test-only single-threaded resolved-import interception observes the pinned DLL; selected failure cases inject one malloc failure and observe the registered callback and real longjmp.',
    'Nonlocal service propagation is traced, not formally proved; arbitrary callbacks, concurrency and whole-interpreter failure selection remain outside this scope.',
]
FAILURE_CASES={
    'create':['create'],
    'set':['create','shared-set','grow-set','error'],
    'slice':['create','shared-set','grow-set','empty-slice','error'],
}

def prepare(base, output, *, descriptor_layout=None, descriptor_revision=None):
    started=time.monotonic()
    plan,_=load_comparison_package(base)
    if plan['target_id']!='jq' or plan['original']['files'].get('runtime/libjq-1.dll')!=ORIGINAL:
        raise ValueError('requires the pinned PE32 jq comparison package')
    if (descriptor_layout is None)!=(descriptor_revision is None):
        raise ValueError('a custom descriptor layout requires its explicit representation revision')
    layout=descriptor_layout or HERE/'value-layout.h'
    revision=descriptor_revision or 'native-layout-arrays-v1'
    output.mkdir(parents=True,exist_ok=False)
    services=definitions(); packages={}; rows=[]
    for name, names in UNITS.items():
        identity='storage-'+name
        setup=output/(identity+'-setup'); setup.mkdir()
        selected={key:services[key] for key in names}
        params,result=SPECS[name]
        intent=component_interface(component_id=identity,types=TYPES,parameters=params,result=result,services=selected)
        (setup/'bridge.c').write_text('#include "portable-component-implementation.h"\n#include "runtime.h"\n#include "comparison-service-bridge.h"\n')
        suppliers=[key for key in names if key in packages and key!=name]
        bindings=bind_dependencies(services={key:packages[key] for key in suppliers})
        recursion=[]
        if name=='release':
            bindings['requirements'].append(dict(id='recursive-release',supplier=identity,contract_sha256='self',kind='internal',service=None))
            recursion=[dict(id='jq-array-destruction',members=[identity],mode='synchronous-comparison',progress='unproved')]
        destination=output/identity
        prepare_comparison_package(interface_package=intent,
            source_files={name+'.c':HERE/(name+'.c'),'value-layout.h':layout,'native-storage.h':HERE/'native-storage.h'},
            operation_symbols={'run':'lifted_storage_'+name},
            target_id='jq',component_id=identity,
            adapter_files={'driver.c':HERE/'driver.c','runtime.c':HERE/'runtime.c','bridge.c':setup/'bridge.c',
                           'allocation-observer.c':HERE/'allocation-observer.c'},
            include_files={'jv.h':base/'headers/jv.h','native.h':HERE/'native.h','runtime.h':HERE/'runtime.h',
                           'allocation-observer.h':HERE/'allocation-observer.h',
                           **native_adapter_headers('pe32-import-hook.h'),
                           'value-layout.h':layout,'native-storage.h':HERE/'native-storage.h','COPYING.jq':HERE/'COPYING.jq'},
            link_files={Path(p).name:base/p for p in plan['link_files']},
            runtime_files={Path(p).name:base/p for p in plan['runtime_files']},
            original_files=['runtime/libjq-1.dll'],oracle_kind='native-original',
            cases=[dict(id='sequence-'+str(n),arguments=[str(n)]) for n in range(11)]+
                [dict(id='generated-'+str(seed),arguments=['generated:'+str(seed)])
                 for seed in [1,7,0x5a17,0x12345678,0x7fffffff,0x80000000,0xa5a5a5a5,0xffffffff]]+
                [dict(id='nomem-'+scenario,arguments=['nomem-'+scenario]) for scenario in FAILURE_CASES.get(name,[])],
            observation_fields=['outcome','entry_length','values','alias_matrix','references','allocation_lifetime','allocation_failure'],assumptions=ASSUMPTIONS,
            scope='Connected authored jq array storage; native-layout finite sequences, original PE32 oracle.',
            compiler=Path(plan['tools']['compiler']['path']),runner=Path(plan['tools']['runner']['path']),
            server=Path(plan['tools']['server']['path']),output=destination,
            **bindings,recursion_groups=recursion,
            export_adapters=['adapters/bridge.c',*(['adapters/runtime.c'] if name=='slice' else [])],
            service_catalog=service_catalog(selected).to_payload() if selected else None,
            service_bridge=dict(adapters={key:dict(symbol='storage_'+key,kind='portable',context=True,outcomes={'return':None}) for key in names},
                                transports={},native_symbol='fixture_storage_'+name),
            representation=dict(group=dict(id='jq-array-storage',label='Shared native-layout array storage',
                members=['storage-'+key for key in UNITS]),revision=revision,
                inputs={'layout':'headers/value-layout.h','descriptor-source':'source/value-layout.h',
                    'native-storage':'headers/native-storage.h','native-storage-source':'source/native-storage.h',
                    'runtime-contract':'headers/runtime.h'}))
        packages[name]=destination
        rows.append(dict(component=identity,package=str(destination),dependencies=['storage-'+key for key in suppliers]))
    write_json(output/'preparation.json',dict(seconds=time.monotonic()-started,base=str(base),
        packages=rows,original_sha256=ORIGINAL,authorizing=False,descriptor_layout=str(layout),descriptor_revision=revision,
        producers={p.name:sha256_file(p) for p in sorted(HERE.iterdir()) if p.is_file()}))
    print(output/'storage-slice')

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('base',type=Path);parser.add_argument('output',type=Path)
    parser.add_argument('--descriptor-layout',type=Path)
    parser.add_argument('--descriptor-revision')
    args=parser.parse_args();prepare(args.base.resolve(),args.output.resolve(),
        descriptor_layout=args.descriptor_layout.resolve() if args.descriptor_layout else None,
        descriptor_revision=args.descriptor_revision)
