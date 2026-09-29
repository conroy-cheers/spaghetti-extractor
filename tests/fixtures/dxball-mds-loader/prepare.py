"""Prepare the MDS loader with shared platform execution and a parser dependency."""
import argparse
from pathlib import Path
import subprocess
import sys
import time
from spaghetti_extractor.components.comparison_composition import bind_dependencies
from spaghetti_extractor.components.comparison_environment import native_adapter_headers,native_environment
from spaghetti_extractor.components.comparison_original import native_entry_header
from spaghetti_extractor.components.comparison_package import prepare_comparison_package
from spaghetti_extractor.components.comparison_wine_environment import wine_test_backend
from spaghetti_extractor.components.service_authoring import OperationDefinition,ServiceDefinition,component_interface,service_catalog
from spaghetti_extractor.util import sha256_file,write_json

HERE=Path(__file__).resolve().parent
PE_SHA256='191c113582e1f31016a158d40372fa21ea68d9348bf847bbfbc8e7c7bdfe195f'
ASSETS=['12flight.mds','Acker-gs.mds','Brain.mds','Ethno_pa.mds','Freebee.mds','Gmfigaro.mds']
NAMES=['memory','file','invalid-zero','invalid-both','memory-high-flags','file-high-flags',
    'memory-allocation-failure','file-allocation-failure','open-failure','size-failure','mapping-failure','view-failure',
    'malformed-memory','malformed-file','parser-allocation-failure','parser-lock-failure','parser-partial-failure',
    'unmap-failure','mapping-close-failure','file-close-failure','info-free-failure','failed-output-history',
    'success-output-history','repeat-success','repeat-failure','zero-memory-length','empty-file','uncompressed','unaligned-memory']
CASES=[dict(id=n,arguments=[str(i)]) for i,n in enumerate(NAMES)]+[
    dict(id='asset-'+kind+'-'+p,arguments=[str(100+group*6+i)]) for group,kind in enumerate(('memory','file')) for i,p in enumerate(ASSETS)]
PARAMETERS=dict(allocate=[('flags','u32'),('bytes','u32')],free=[('info','mds_info')],
    open=[('input','mds_input'),('access','u32'),('share','u32'),('creation','u32'),('attributes','u32')],
    size=[('handle','mds_handle')],mapping=[('handle','mds_handle'),('protection','u32')],
    map=[('handle','mds_handle'),('access','u32')],unmap=[('file','mds_file')],close=[('handle','mds_handle')],
    parse=[('info','mds_info'),('file','mds_file'),('length','u32')])
RESULTS=dict(allocate='mds_info',free='mds_info',open='mds_handle',size='u32',mapping='mds_handle',map='mds_file',unmap='u32',close='u32',parse='u32')
NOMINALS={n:'dxball.mds.'+n.removeprefix('mds_') for n in ('mds_info','mds_file','mds_input','mds_output','mds_handle')}
TYPES=[dict(id='u32',kind='integer',width_bits=32,signed=False),*[dict(id=n,kind='opaque',nominal_id=v) for n,v in NOMINALS.items()]]
C_TYPES=dict(u32='uint32_t',**{n:n+' *' for n in NOMINALS})

def bridge_spec():
    return dict(adapters={n:dict(symbol='loader_'+n,kind='portable',context=True,outcomes={'return':None}) for n in PARAMETERS},transports={},native_symbol=None)

def bridge():
    return '''#include "portable-component-implementation.h"
#include "mds-loader-runtime.h"
#include "comparison-service-bridge.h"
uint32_t fixture_mds_load(mds_output *output,mds_input *input,uint32_t length,uint32_t flags) {
    loader_enter();spx_mds_loader_services_v5 services=spx_mds_loader_bind_services(NULL);
    spx_mds_loader_context_v5 context={0};context.services=&services;spx_mds_loader_services_begin();
    uint32_t result=lifted_mds_load(&context,output,input,length,flags);spx_mds_loader_services_end();return result;
}
'''

def runtime_header():
    text='#ifndef DXBALL_MDS_LOADER_RUNTIME_H\n#define DXBALL_MDS_LOADER_RUNTIME_H\n#include "mds-loader-state.h"\nvoid loader_enter(void);\nuint32_t fixture_mds_load(mds_output *,mds_input *,uint32_t,uint32_t);\n'
    for n,p in PARAMETERS.items():text+=C_TYPES[RESULTS[n]]+' loader_'+n+'(void *'+''.join(', '+C_TYPES[t] for _,t in p)+');\n'
    return text+'#endif\n'

def prepare(original,parser,output):
    started=time.monotonic();output.mkdir(parents=True,exist_ok=False)
    if sha256_file(original)!=PE_SHA256:raise ValueError('requires pinned DX-Ball image')
    services={n:ServiceDefinition.create(identity='dxball.mds.loader.'+n,types=TYPES,parameters=p,result=RESULTS[n],
        nullable_result=n in ('allocate','free','open','mapping','map'),resources=[],effects=['dxball.mds.loader.'+n],outcomes=['return'],
        unobserved=['Shared info and storage lifetime correspondence is explicit in BOUNDARY.md; no checked universal heap summary.']) for n,p in PARAMETERS.items()}
    interface=component_interface(component_id='mds-loader',types=TYPES,services=services,
        operations={'load':OperationDefinition([('output','mds_output'),('input','mds_input'),('length','u32'),('flags','u32')],'u32',list(PARAMETERS))})
    catalog=service_catalog(services).to_payload()
    write_json(output/'interface.json',interface.to_payload());write_json(output/'services.json',catalog);write_json(output/'bridge.json',bridge_spec())
    (output/'bridge.c').write_text(bridge());(output/'mds-loader-runtime.h').write_text(runtime_header())
    sources={'loader.c':HERE/'loader.c','mds-loader-state.h':HERE/'mds-loader-state.h',
        **{n:parser/'source'/n for n in ('mds-state.h','mds-events-state.h')}}
    args=['component','start','dxball','mds-loader','--interface-intent',str(output/'interface.json'),
        '--service-catalog',str(output/'services.json'),'--service-bridge',str(output/'bridge.json'),
        '--assumption-file',str(HERE/'BOUNDARY.md'),'--remove-source','source/component.c',
        '--operation-symbol','load=lifted_mds_load','--output',str(output/'authoring')]
    for name,path in sources.items():args+=['--source-file','source/'+name+'='+str(path)]
    ran=subprocess.run([sys.executable,'-m','spaghetti_extractor',*args],capture_output=True,text=True)
    (output/'start.stdout').write_text(ran.stdout);(output/'start.stderr').write_text(ran.stderr)
    if ran.returncode:raise ValueError('inspect start.stderr')
    (output/'native-image.h').write_text((parser/'headers/native-image.h').read_text()+'\n'+native_entry_header(
        original=original,expected_sha256=PE_SHA256,module=None,entry_rva=0x1a20,end_rva=0x1b60,installer='install_mds_load'))
    backend=wine_test_backend();environment=native_environment(parser)
    prepare_comparison_package(interface_package=output/'authoring/interface.json',source_files={n:output/'authoring/source'/n for n in sources},
        operation_symbols={'load':'lifted_mds_load'},target_id='dxball',component_id='mds-loader',
        adapter_files={**backend['adapter_files'],'runtime.c':HERE/'runtime.c','bridge.c':output/'bridge.c'},
        include_files={**backend['include_files'],**native_adapter_headers('pe32-entry-hook.h'),
            'native-image.h':output/'native-image.h','mds-loader-runtime.h':output/'mds-loader-runtime.h',
            **{n:parser/'headers'/n for n in ('mds-parser-runtime.h','mds-events-runtime.h','mds-transport.c')},
            'loader-transport.c':HERE/'loader-transport.c'},
        **bind_dependencies(services={'parse':parser}),**environment,original_files=['runtime/DXBall.exe'],oracle_kind='native-original',
        cases=CASES,observation_fields=['mds_loader'],assumptions=[(HERE/'BOUNDARY.md').read_text()],
        scope='MDS file/memory loading with exact output publication, parser composition and shared mapped-storage cleanup; no game startup.',
        service_catalog=catalog,service_bridge=bridge_spec(),export_adapters=['adapters/bridge.c'],
        program_driver=dict(kind='pe32-import',image='runtime/DXBall.exe',library='dx-mds-loader.dll',symbol='dx_mds_loader_anchor'),output=output/'mds-loader')
    write_json(output/'preparation.json',dict(seconds=time.monotonic()-started,cases=len(CASES),original_source_consulted=False,tool_internal_changes=False))

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('original','parser','output'):p.add_argument(name,type=Path)
    a=p.parse_args();prepare(a.original.resolve(),a.parser.resolve(),a.output.resolve())
