"""Prepare MDS stream control and completion over shared loader and MIDI services."""
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
RANGES=dict(start=(0x1ea0,0x1fe0),pause=(0x1fe0,0x2026),stop=(0x2030,0x20bb),complete=(0x20c0,0x20f6),release=(0x1e40,0x1e9b))
ASSETS=['12flight.mds','Acker-gs.mds','Brain.mds','Ethno_pa.mds','Freebee.mds','Gmfigaro.mds']
NAMES=['start-stop-release','loop-completion','nonloop-completion','pause-resume','already-started','pause-twice',
    'bad-signature-start','bad-signature-pause','bad-signature-stop','bad-signature-release','pause-without-stream','stop-without-stream',
    'open-failure','open-failed-publication','property-failure','first-prepare-failure','second-prepare-failure','first-queue-failure','second-queue-failure',
    'restart-failure','pause-failure','reset-failure','unprepare-failure','close-failure','callback-requeue-failure',
    'pending-underflow','pending-overflow','ignored-callback','high-flags','zero-buffers','deferred-reset','release-without-start',
    'release-free-failure','release-unlock-failure','release-info-free-failure','resume-restart-failure','reopen-after-stop',
    'callback-stopping','loop-low-bit','two-live-streams','release-reset-failure','zero-payload','provider-linked-header','provider-read-interleave']
CASES=[dict(id=n,arguments=[str(i)]) for i,n in enumerate(NAMES)]+[dict(id='asset-'+p,arguments=[str(100+i)]) for i,p in enumerate(ASSETS)]
PARAMETERS={n:[('info','mds_info')] for n in ('restart','pause','reset','close','free_info')}
PARAMETERS.update(open=[('info','mds_info'),('device','u32'),('count','u32'),('flags','u32')],
    property=[('info','mds_info'),('size','u32'),('division','u32'),('flags','u32')],
    **{n:[('info','mds_info'),('header','mds_header'),('size','u32')] for n in ('prepare','queue','unprepare')},
    allocation=[('buffers','mds_buffers')],unlock=[('memory','mds_memory')],free_buffers=[('memory','mds_memory')])
RESULTS={n:'u32' for n in PARAMETERS};RESULTS.update(allocation='mds_memory',free_buffers='mds_memory',free_info='mds_info')
NOMINALS={n:'dxball.mds.'+n.removeprefix('mds_') for n in ('mds_info','mds_header','mds_buffers','mds_memory')}
TYPES=[dict(id='unit',kind='void'),dict(id='u32',kind='integer',width_bits=32,signed=False),*[dict(id=n,kind='opaque',nominal_id=v) for n,v in NOMINALS.items()]]
C_TYPES=dict(unit='void',u32='uint32_t',**{n:n+' *' for n in NOMINALS})
OPS={n:([('message','u32'),('header','mds_header')] if n=='complete' else [('info','mds_info')]+([('loop','u32')] if n=='start' else [])) for n in RANGES}

def bridge_spec():
    return dict(adapters={n:dict(symbol='stream_'+n,kind='portable',context=True,outcomes={'return':None}) for n in PARAMETERS},transports={},native_symbol=None)

def bridge():
    text='#include "portable-component-implementation.h"\n#include "mds-stream-runtime.h"\n#include "comparison-service-bridge.h"\n'
    for i,(name,params) in enumerate(OPS.items()):
        result='void' if name=='complete' else 'uint32_t';args=','.join(C_TYPES[t]+' '+n for n,t in params)
        text+=f'{result} fixture_mds_{name}({args}) {{\n    stream_enter({i});spx_mds_stream_services_v5 services=spx_mds_stream_bind_services(NULL);\n    spx_mds_stream_context_v5 context={{0}};context.services=&services;spx_mds_stream_services_begin();\n'
        text+=('    ' if name=='complete' else '    uint32_t result=')+'lifted_mds_'+name+'(&context,'+','.join(n for n,_ in params)+');spx_mds_stream_services_end();'
        text+=('' if name=='complete' else 'return result;')+'\n}\n'
    return text

def runtime_header():
    text='#ifndef DXBALL_MDS_STREAM_RUNTIME_H\n#define DXBALL_MDS_STREAM_RUNTIME_H\n#include "mds-stream-state.h"\nvoid stream_enter(unsigned);\n'
    for n,params in OPS.items():text+=('void' if n=='complete' else 'uint32_t')+' fixture_mds_'+n+'('+','.join(C_TYPES[t] for _,t in params)+');\n'
    for n,p in PARAMETERS.items():text+=C_TYPES[RESULTS[n]]+' stream_'+n+'(void *'+''.join(', '+C_TYPES[t] for _,t in p)+');\n'
    return text+'#endif\n'

def prepare(original,loader,output):
    started=time.monotonic();output.mkdir(parents=True,exist_ok=False)
    if sha256_file(original)!=PE_SHA256:raise ValueError('requires pinned DX-Ball image')
    services={n:ServiceDefinition.create(identity='dxball.mds.stream.'+n,types=TYPES,parameters=p,result=RESULTS[n],
        nullable_result=n in ('allocation','free_buffers','free_info'),nullable_parameters=['memory'] if n in ('unlock','free_buffers') else [],
        resources=[],effects=['dxball.mds.stream.'+n],outcomes=['return'],
        unobserved=['Shared buffer geometry, callback updates and lifetime correspondence in BOUNDARY.md; no universal heap/concurrency proof.']) for n,p in PARAMETERS.items()}
    interface=component_interface(component_id='mds-stream',types=TYPES,services=services,
        operations={n:OperationDefinition(p,'unit' if n=='complete' else 'u32',list(PARAMETERS),nullable_parameters=['header'] if n=='complete' else []) for n,p in OPS.items()})
    catalog=service_catalog(services).to_payload()
    write_json(output/'interface.json',interface.to_payload());write_json(output/'services.json',catalog);write_json(output/'bridge.json',bridge_spec())
    (output/'bridge.c').write_text(bridge());(output/'mds-stream-runtime.h').write_text(runtime_header())
    sources={'stream.c':HERE/'stream.c','mds-stream-state.h':HERE/'mds-stream-state.h',
        **{n:loader/'source'/n for n in ('mds-state.h','mds-events-state.h','mds-loader-state.h')}}
    args=['component','start','dxball','mds-stream','--interface-intent',str(output/'interface.json'),
        '--service-catalog',str(output/'services.json'),'--service-bridge',str(output/'bridge.json'),
        '--assumption-file',str(HERE/'BOUNDARY.md'),'--remove-source','source/component.c','--output',str(output/'authoring')]
    for n in OPS:args+=['--operation-symbol',n+'=lifted_mds_'+n]
    for name,path in sources.items():args+=['--source-file','source/'+name+'='+str(path)]
    ran=subprocess.run([sys.executable,'-m','spaghetti_extractor',*args],capture_output=True,text=True)
    (output/'start.stdout').write_text(ran.stdout);(output/'start.stderr').write_text(ran.stderr)
    if ran.returncode:raise ValueError('inspect start.stderr')
    (output/'native-image.h').write_text((loader/'headers/native-image.h').read_text()+'\n'+'\n'.join(native_entry_header(
        original=original,expected_sha256=PE_SHA256,module=None,entry_rva=lo,end_rva=hi,installer='install_mds_'+n) for n,(lo,hi) in RANGES.items()))
    backend=wine_test_backend();environment=native_environment(loader)
    prepare_comparison_package(interface_package=output/'authoring/interface.json',source_files={n:output/'authoring/source'/n for n in sources},
        operation_symbols={n:'lifted_mds_'+n for n in OPS},target_id='dxball',component_id='mds-stream',
        adapter_files={**backend['adapter_files'],'runtime.c':HERE/'runtime.c','bridge.c':output/'bridge.c'},
        include_files={**backend['include_files'],**native_adapter_headers('pe32-entry-hook.h'),
            'native-image.h':output/'native-image.h','mds-stream-runtime.h':output/'mds-stream-runtime.h',
            **{n:loader/'headers'/n for n in ('mds-loader-runtime.h','mds-parser-runtime.h','mds-events-runtime.h','mds-transport.c','loader-transport.c')},
            'mds-transport.c':HERE.parent/'dxball-mds-parser/mds-transport.c',
            'stream-transport.c':HERE/'stream-transport.c'},
        **bind_dependencies(consumers={'loaded-info':loader}),**environment,original_files=['runtime/DXBall.exe'],oracle_kind='native-original',
        cases=CASES,observation_fields=['mds_stream'],assumptions=[(HERE/'BOUNDARY.md').read_text()],
        scope='Connected MDS loading, playback, callback requeue and release over shared platform lifetimes; no game startup.',
        service_catalog=catalog,service_bridge=bridge_spec(),export_adapters=['adapters/bridge.c'],
        program_driver=dict(kind='pe32-import',image='runtime/DXBall.exe',library='dx-mds-stream.dll',symbol='dx_mds_stream_anchor'),output=output/'mds-stream')
    write_json(output/'preparation.json',dict(seconds=time.monotonic()-started,cases=len(CASES),original_source_consulted=False,tool_internal_changes=False))

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('original','loader','output'):p.add_argument(name,type=Path)
    a=p.parse_args();prepare(a.original.resolve(),a.loader.resolve(),a.output.resolve())
