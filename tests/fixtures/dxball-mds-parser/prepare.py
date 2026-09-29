"""Prepare MDS parsing over shared storage and the independently lifted expander."""
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
NAMES=['compact','uncompressed','empty-blocks','zero-count','short-riff','bad-riff','bad-mids','oversized-riff',
    'missing-format','short-format','oversized-format','extended-format','missing-data','short-data','oversized-data',
    'declared-length-before-count','short-block-header','oversized-block','truncated-block','delta-only',
    'unaligned-event-length','expansion-capacity','invalid-second-block','allocation-failure','lock-failure',
    'unlock-failure','free-failure','padded-long-events','ignored-format-bits','unaligned-headers','zero-capacity',
    'repeat-partial-failure','repeat-early-failure','count-product-wrap','capacity-sum-wrap','unaligned-file']
CASES=[dict(id=n,arguments=[str(i)]) for i,n in enumerate(NAMES)]+[
    dict(id='asset-'+p,arguments=[str(100+i)]) for i,p in enumerate(ASSETS)]
PARAMETERS=dict(allocate=[('flags','u32'),('bytes','u32')],lock=[('info','mds_info'),('memory','mds_memory')],
    allocation=[('buffers','mds_buffers')],unlock=[('memory','mds_memory')],free=[('memory','mds_memory')],
    expand=[('input','mds_event_block'),('output','mds_event_block')])
RESULTS=dict(allocate='mds_memory',lock='mds_buffers',allocation='mds_memory',unlock='u32',free='mds_memory',expand='u32')
NOMINALS={**{n:'dxball.mds.'+n.removeprefix('mds_') for n in ('mds_info','mds_file','mds_buffers','mds_memory')},
    'mds_event_block':'dxball.mds.event-block'}
TYPES=[dict(id='u32',kind='integer',width_bits=32,signed=False),*[dict(id=n,kind='opaque',nominal_id=v) for n,v in NOMINALS.items()]]
C_TYPES=dict(u32='uint32_t',**{n:n+' *' for n in NOMINALS})

def bridge_spec():
    return dict(adapters={n:dict(symbol='parser_'+n,kind='portable',context=True,outcomes={'return':None}) for n in PARAMETERS},transports={},native_symbol=None)

def bridge():
    return '''#include "portable-component-implementation.h"
#include "mds-parser-runtime.h"
#include "comparison-service-bridge.h"
uint32_t fixture_mds_parse(mds_info *info,mds_file *file,uint32_t length) {
    parser_enter();spx_mds_parser_services_v5 services=spx_mds_parser_bind_services(NULL);
    spx_mds_parser_context_v5 context={0};context.services=&services;spx_mds_parser_services_begin();
    uint32_t result=lifted_mds_parse(&context,info,file,length);spx_mds_parser_services_end();return result;
}
'''

def runtime_header():
    text='#ifndef DXBALL_MDS_PARSER_RUNTIME_H\n#define DXBALL_MDS_PARSER_RUNTIME_H\n#include "mds-state.h"\nvoid parser_enter(void);\nuint32_t fixture_mds_parse(mds_info *,mds_file *,uint32_t);\n'
    for n,p in PARAMETERS.items():text+=C_TYPES[RESULTS[n]]+' parser_'+n+'(void *'+''.join(', '+C_TYPES[t] for _,t in p)+');\n'
    return text+'#endif\n'

def prepare(original,events,output):
    started=time.monotonic();output.mkdir(parents=True,exist_ok=False)
    if sha256_file(original)!=PE_SHA256:raise ValueError('requires pinned DX-Ball image')
    services={n:ServiceDefinition.create(identity='dxball.mds.'+n,types=TYPES,parameters=p,result=RESULTS[n],
        nullable_result=n in ('allocate','lock','allocation','free'),nullable_parameters=['memory'] if n in ('lock','unlock','free') else [],
        resources=[],effects=['dxball.mds.'+n],outcomes=['return'],
        unobserved=['Explicit header geometry, pointer history, allocation and lock lifetime correspondence in BOUNDARY.md; no checked heap summary.']) for n,p in PARAMETERS.items()}
    interface=component_interface(component_id='mds-parser',types=TYPES,services=services,
        operations={'parse':OperationDefinition([('info','mds_info'),('file','mds_file'),('length','u32')],'u32',list(PARAMETERS))})
    catalog=service_catalog(services).to_payload()
    write_json(output/'interface.json',interface.to_payload());write_json(output/'services.json',catalog);write_json(output/'bridge.json',bridge_spec())
    (output/'bridge.c').write_text(bridge());(output/'mds-parser-runtime.h').write_text(runtime_header())
    sources={'parser.c':HERE/'parser.c','mds-state.h':HERE/'mds-state.h','mds-events-state.h':events/'source/mds-events-state.h'}
    args=['component','start','dxball','mds-parser','--interface-intent',str(output/'interface.json'),
        '--service-catalog',str(output/'services.json'),'--service-bridge',str(output/'bridge.json'),
        '--assumption-file',str(HERE/'BOUNDARY.md'),'--remove-source','source/component.c',
        '--operation-symbol','parse=lifted_mds_parse','--output',str(output/'authoring')]
    for name,path in sources.items():args+=['--source-file','source/'+name+'='+str(path)]
    ran=subprocess.run([sys.executable,'-m','spaghetti_extractor',*args],capture_output=True,text=True)
    (output/'start.stdout').write_text(ran.stdout);(output/'start.stderr').write_text(ran.stderr)
    if ran.returncode:raise ValueError('inspect start.stderr')
    (output/'native-image.h').write_text((events/'headers/native-image.h').read_text()+'\n'+native_entry_header(
        original=original,expected_sha256=PE_SHA256,module=None,entry_rva=0x1b60,end_rva=0x1d5d,installer='install_mds_parse'))
    backend=wine_test_backend();environment=native_environment(events)
    prepare_comparison_package(interface_package=output/'authoring/interface.json',source_files={n:output/'authoring/source'/n for n in sources},
        operation_symbols={'parse':'lifted_mds_parse'},target_id='dxball',component_id='mds-parser',
        adapter_files={**backend['adapter_files'],'runtime.c':HERE/'runtime.c','bridge.c':output/'bridge.c'},
        include_files={**backend['include_files'],**native_adapter_headers('pe32-entry-hook.h'),
            'native-image.h':output/'native-image.h','mds-parser-runtime.h':output/'mds-parser-runtime.h',
            'mds-events-runtime.h':events/'headers/mds-events-runtime.h','mds-transport.c':HERE/'mds-transport.c'},
        **bind_dependencies(services={'expand':events}),**environment,original_files=['runtime/DXBall.exe'],oracle_kind='native-original',
        cases=CASES,observation_fields=['mds_parser'],assumptions=[(HERE/'BOUNDARY.md').read_text()],
        scope='MDS container parsing with exact header history, shared global storage, error cleanup and all six bundled assets; no game startup.',
        service_catalog=catalog,service_bridge=bridge_spec(),export_adapters=['adapters/bridge.c'],
        program_driver=dict(kind='pe32-import',image='runtime/DXBall.exe',library='dx-mds-parser.dll',symbol='dx_mds_parser_anchor'),output=output/'mds-parser')
    write_json(output/'preparation.json',dict(seconds=time.monotonic()-started,cases=len(CASES),original_source_consulted=False,tool_internal_changes=False))

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('original','events','output'):p.add_argument(name,type=Path)
    a=p.parse_args();prepare(a.original.resolve(),a.events.resolve(),a.output.resolve())
