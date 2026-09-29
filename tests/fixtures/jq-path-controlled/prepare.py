"""Author a path-get boundary from retained jq runtime inputs and C adapters.

No prepared path-get interface or source package is needed. Optional authored
array packages keep the real shared-storage services selected while get itself
uses explicit controlled transcripts. This recipe calls public authoring APIs.
"""
import argparse
from dataclasses import asdict
import json
from pathlib import Path
import sys
import time

from spaghetti_extractor.components.comparison_package import load_comparison_package, prepare_comparison_package, retained_comparison_environment
from spaghetti_extractor.components.comparison_composition import requirement
from spaghetti_extractor.components.comparison_environment import native_adapter_headers
from spaghetti_extractor.components.service_authoring import component_interface, service_catalog

HERE=Path(__file__).resolve().parent
PATHS=HERE.parent/'jq-path-network'
ARRAYS=HERE.parent/'jq-array-storage'
VALUES=HERE.parent/'jq-value-transport'
# Target declarations and adapters are ordinary reusable authoring inputs.
sys.path.insert(0,str(PATHS))
from services import library, types, TRANSPORTS, V
from prepare import resource_checks

def prepare(base,output,arrays=None):
    started=time.monotonic()
    plan,base_interface=load_comparison_package(base)
    if plan['target_id']!='jq' or plan['original']['files'].get('runtime/libjq-1.dll')!='50d05ffd1f3cdbb5257f2cda429d9b920d95c091bb88a9d8bcdcb08ae9bacb1d':
        raise ValueError('requires the retained pinned jq runtime')
    environment=retained_comparison_environment(base)
    definitions,adapters=library(base_interface.to_payload(),nonlocal_allocation=bool(arrays))
    names=['copy','kind','valid','release','length','array_get','array_slice','get','error']
    selected={name:definitions[name] for name in names}
    interface=component_interface(component_id='path-get',types=types(base_interface.to_payload()),
        parameters=[('root',V),('key',V)],result=V,services=selected)
    dependencies=[];requirements=[]
    array_services={'copy':'copy','release':'release','length':'length','array_get':'get','array_slice':'slice'}
    if arrays:
        for name,supplier in array_services.items():
            package=arrays/('storage-'+supplier);supplier_plan,_=load_comparison_package(package)
            if supplier_plan['original']!=plan['original']:
                raise ValueError('selected array supplier binds another original')
            requirements.append(requirement(identity='array-storage-'+name,supplier='storage-'+supplier,
                root=package,unit=supplier_plan,kind='service',service=name))
            adapters[name]=dict(adapters[name],symbol='path_storage_'+name)
        dependencies=[dict(id='storage-'+name,package=arrays/('storage-'+name)) for name in ['slice','length']]
    output.mkdir(parents=True,exist_ok=False)
    bridge=output/'bridge.c'
    bridge.write_text('#include "portable-component-implementation.h"\n#include "native-api.h"\n'
        '#include "value-transport.h"\n#include "native-services.h"\n'+
        ('#include "array-path-bridge.h"\n' if arrays else '')+'#include "comparison-service-bridge.h"\n')
    service_bridge=dict(adapters={name:adapters[name] for name in names},
        transports={name:asdict(value) for name,value in TRANSPORTS.items()},native_symbol='fixture_path_get')
    scenarios=json.loads((HERE/'scenarios.json').read_text())
    cases=[]
    for scenario in scenarios:
        cases.append(dict(id=scenario['id'],arguments=[json.dumps(scenario['root']),json.dumps(scenario['path']),json.dumps(scenario['steps']),'caller']))
    for name,rows in [('caller',cases),('service',[dict(id=s['id']+'-'+str(n),arguments=[json.dumps(step['root']),json.dumps(step['key']),json.dumps([step]),'service']) for s in scenarios for n,step in enumerate(s['steps'])])]:
        caller=name=='caller'
        headers={'jv.h':base/'headers/jv.h','native-api.h':PATHS/'native-api.h',
            'native-services.h':PATHS/'native-services.h','path-contract.h':PATHS/'path-contract.h',
            'value-transport.h':VALUES/'value-transport.h',
            'value-runtime-impl.h':VALUES/('observed-runtime.h' if caller else 'raw-runtime.h'),
            **native_adapter_headers('pe32-entry-hook.h')}
        if arrays and caller:
            storage_headers=arrays/'storage-slice/headers'
            headers.update({'array-path-bridge.h':ARRAYS/'path-bridge.h','array-native.h':storage_headers/'native.h',
                'runtime.h':storage_headers/'runtime.h','value-layout.h':storage_headers/'value-layout.h',
                **({'native-storage.h':storage_headers/'native-storage.h'} if (storage_headers/'native-storage.h').is_file() else {}),
                'allocation-observer.h':ARRAYS/'allocation-observer.h',**native_adapter_headers('pe32-import-hook.h')})
        mode=output/(name+'-mode.h')
        mode.write_text('#define CONTROLLED_SERVICE_ONLY '+str(int(not caller))+'\n'
            '#define CONTROLLED_ARRAY_STORAGE '+str(int(bool(arrays) and caller))+'\n')
        headers['controlled-mode.h']=mode
        prepare_comparison_package(interface_package=interface,source_files={'getpath.c':PATHS/'getpath.c'},
            operation_symbols={'run':'lifted_path_get'},target_id='jq',component_id='path-get',
            adapter_files={'driver.c':HERE/'driver.c',**({'bridge.c':bridge} if caller else {}),
                **({'allocation-observer.c':ARRAYS/'allocation-observer.c'} if arrays and caller else {}),
                'errors.c':PATHS/'native-errors.c','value-runtime.c':VALUES/'value-runtime.c'},
            include_files=headers,
            original_files=['runtime/libjq-1.dll'],oracle_kind='native-original',cases=rows,
            observation_fields=['outcome','root_after','key_after','calls','body_absence','references','allocation_lifetime'],
            assumptions=['Finite explicit get transcripts; logical equality and consumed references; no allocation-failure simulation',
                'Caller mode removes pinned native jv_get body on both sides; authored get body absent; service mode separately checks native outcomes',
                'Returned transcript values have fixture-owned storage; alias equivalence to native get results is not established',
                'Real native-layout array services are selected for caller mode' if arrays else 'Native storage, allocation and lifetime services are retained'],
            scope='jq controlled get '+name+'; finite executable local evidence, not a checked summary',
            resource_checks=resource_checks(interface,nonlocal_allocation=bool(arrays)) if caller else None,
            service_catalog=service_catalog(selected).to_payload() if caller else None,
            service_bridge=service_bridge if caller else None,output=output/name,
            dependencies=dependencies if caller else [],requirements=requirements if caller else None,
            **environment)
    (output/'preparation.json').write_text(json.dumps(dict(seconds=time.monotonic()-started,base=str(base),
        arrays=str(arrays) if arrays else None,interface_intent_sha256=interface.intent_sha256,
        manual_inputs=['run parameters and result','selected services','resource scope','C sources and adapters','scenario cases'],
        generated=['interface and source identities','C headers and service bridges','dependency graph','comparison packages'],
        per_component_tool_internal_changes=False,authorizing=False),indent=2)+'\n')
    return output

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('base',type=Path);p.add_argument('output',type=Path)
    p.add_argument('--array-storage-packages',type=Path)
    a=p.parse_args();print(prepare(a.base.resolve(),a.output.resolve(),a.array_storage_packages.resolve() if a.array_storage_packages else None))
