"""Prepare the binary-derived music controller over declared application services."""
import argparse
from pathlib import Path
import subprocess
import sys
import time
from spaghetti_extractor.components.comparison_environment import native_environment,native_adapter_headers,observation_headers
from spaghetti_extractor.components.comparison_original import native_entry_header
from spaghetti_extractor.components.comparison_package import prepare_comparison_package
from spaghetti_extractor.components.service_authoring import OperationDefinition,ServiceDefinition,component_interface,service_catalog
from spaghetti_extractor.util import sha256_file,write_json

HERE=Path(__file__).resolve().parent
PE_SHA256='191c113582e1f31016a158d40372fa21ea68d9348bf847bbfbc8e7c7bdfe195f'
RANGES=dict(play=(0x2100,0x2197),resume=(0x21a0,0x21c8),pause=(0x21d0,0x21f2),stop=(0x2200,0x223e))
HOOKS=dict(allocate_record=0xdf40,free_record=0xdf30,load=0x1a20,start_stream=0x1ea0,pause_stream=0x1fe0,stop_stream=0x2030,release_stream=0x1e40)
OP_PARAMETERS={n:[('state','music_state'),*([('name','music_name'),('start','u32')] if n=='play' else [])] for n in RANGES}
ARGS=dict(allocate_record=[('bytes','u32')],free_record=[('record','music_record')],
    load=[('record','music_record'),('name','music_name'),('length','u32'),('flags','u32')],
    start_stream=[('stream','music_stream'),('loop','u32')],pause_stream=[('stream','music_stream')],
    stop_stream=[('stream','music_stream')],release_stream=[('stream','music_stream')])
PARAMETERS={n:[('state','music_state'),*p] for n,p in ARGS.items()}
RESULTS={n:'music_record' if n=='allocate_record' else 'unit' if n=='free_record' else 'u32' for n in PARAMETERS}
NOMINALS={n:'dxball.music.'+n.removeprefix('music_') for n in ('music_state','music_record','music_stream','music_name')}
TYPES=[dict(id='unit',kind='void'),dict(id='u32',kind='integer',width_bits=32,signed=False),*[dict(id=n,kind='opaque',nominal_id=v) for n,v in NOMINALS.items()]]
C_TYPES=dict(unit='void',u32='uint32_t',**{n:n+' *' for n in NOMINALS})
NAMES=['load-unstarted','load-and-start','nonboolean-start','replace-existing','allocation-failure','load-failure','load-high-error',
    'start-failure','start-high-error','resume-empty','resume','resume-failure','pause-empty','pause','pause-failure','stop-empty','stop',
    'stop-failure-ignored','release-failure-ignored','load-root-redirection','start-root-redirection','failed-start-root-redirection',
    'failure-release-root-redirection','stop-root-redirection','stop-release-root-redirection','free-root-redirection',
    'resume-root-redirection','pause-root-redirection','allocation-root-redirection','play-pause-resume-stop']
CASES=[dict(id=n,arguments=[str(i)]) for i,n in enumerate(NAMES)]

def bridge_spec():
    return dict(adapters={n:dict(symbol='music_'+n,kind='portable',context=True,outcomes={'return':None}) for n in PARAMETERS},transports={},native_symbol=None)

def bridge():
    text='#include "portable-component-implementation.h"\n#include "music-runtime.h"\n#include "comparison-service-bridge.h"\n'
    for i,n in enumerate(RANGES):
        result='uint32_t' if n=='play' else 'void'
        text+=result+' fixture_music_'+n+'('+','.join(C_TYPES[t]+' '+p for p,t in OP_PARAMETERS[n])+') {\n'
        text+=f'    music_enter({i});spx_music_control_services_v5 services=spx_music_control_bind_services(NULL);\n    spx_music_control_context_v5 context={{0}};context.services=&services;spx_music_control_services_begin();\n'
        text+=('    uint32_t result=' if n=='play' else '    ')+f'lifted_music_{n}(&context,'+','.join(p for p,_ in OP_PARAMETERS[n])+');spx_music_control_services_end();'
        text+=('return result;' if n=='play' else '')+'\n}\n'
    return text

def runtime_header():
    text='#ifndef DXBALL_MUSIC_RUNTIME_H\n#define DXBALL_MUSIC_RUNTIME_H\n#include "music-state.h"\nvoid music_enter(unsigned);\n'
    for n in RANGES:text+=('uint32_t' if n=='play' else 'void')+' fixture_music_'+n+'('+','.join(C_TYPES[t] for _,t in OP_PARAMETERS[n])+');\n'
    for n,p in PARAMETERS.items():text+=C_TYPES[RESULTS[n]]+' music_'+n+'(void *'+''.join(', '+C_TYPES[t] for _,t in p)+');\n'
    return text+'enum { '+', '.join('MUSIC_SERVICE_'+n.upper()+'='+str(i) for i,n in enumerate(PARAMETERS))+' };\n#endif\n'

def prepare(original,environment_package,output):
    started=time.monotonic();output.mkdir(parents=True,exist_ok=False)
    if sha256_file(original)!=PE_SHA256:raise ValueError('requires pinned DX-Ball image')
    services={n:ServiceDefinition.create(identity='dxball.music.'+n,types=TYPES,parameters=p,result=RESULTS[n],resources=[],
        effects=['dxball.music.'+n],outcomes=['return'],unobserved=['Application record/stream ownership and callback assumptions are explicit in BOUNDARY.md; lower MIDI implementation is retained.']) for n,p in PARAMETERS.items()}
    interface=component_interface(component_id='music-control',types=TYPES,services=services,
        operations={n:OperationDefinition(p,'u32' if n=='play' else 'unit',list(PARAMETERS)) for n,p in OP_PARAMETERS.items()})
    catalog=service_catalog(services).to_payload();write_json(output/'interface.json',interface.to_payload());write_json(output/'services.json',catalog);write_json(output/'bridge.json',bridge_spec())
    (output/'bridge.c').write_text(bridge());(output/'music-runtime.h').write_text(runtime_header())
    args=['component','start','dxball','music-control','--interface-intent',str(output/'interface.json'),'--service-catalog',str(output/'services.json'),
        '--service-bridge',str(output/'bridge.json'),'--assumption-file',str(HERE/'BOUNDARY.md'),'--remove-source','source/component.c','--output',str(output/'authoring')]
    for n in RANGES:args+=['--operation-symbol',n+'=lifted_music_'+n]
    for n in ('music.c','music-state.h'):args+=['--source-file','source/'+n+'='+str(HERE/n)]
    ran=subprocess.run([sys.executable,'-m','spaghetti_extractor',*args],capture_output=True,text=True)
    (output/'start.stdout').write_text(ran.stdout);(output/'start.stderr').write_text(ran.stderr)
    if ran.returncode:raise ValueError('inspect start.stderr')
    entries=dict(startup=(0xeaa0,0xeaa8),**{'music_'+n:r for n,r in RANGES.items()},**{'music_service_'+n:(lo,lo+8) for n,lo in HOOKS.items()})
    (output/'native-image.h').write_text('\n'.join(native_entry_header(original=original,expected_sha256=PE_SHA256,module=None,entry_rva=lo,end_rva=hi,
        installer='install_'+n) for n,(lo,hi) in entries.items()))
    environment=native_environment(environment_package)
    prepare_comparison_package(interface_package=output/'authoring/interface.json',source_files={n:output/'authoring/source'/n for n in ('music.c','music-state.h')},
        operation_symbols={n:'lifted_music_'+n for n in RANGES},target_id='dxball',component_id='music-control',
        adapter_files={'runtime.c':HERE/'runtime.c','bridge.c':output/'bridge.c'},
        include_files={**observation_headers(),**native_adapter_headers('pe32-entry-hook.h'),'native-image.h':output/'native-image.h','music-runtime.h':output/'music-runtime.h'},
        **{**environment,'runtime_files':{**environment['runtime_files'],'DXBall.exe':original}},original_files=['runtime/DXBall.exe'],oracle_kind='native-original',
        cases=CASES,observation_fields=['music'],assumptions=[(HERE/'BOUNDARY.md').read_text()],
        scope='Four music-controller entries over shared current record, application library services, failure cleanup and synchronous callback root redirection; no game startup or MIDI emulation.',
        service_catalog=catalog,service_bridge=bridge_spec(),export_adapters=['adapters/bridge.c'],
        program_driver=dict(kind='pe32-import',image='runtime/DXBall.exe',library='dx-music.dll',symbol='dx_music_anchor'),output=output/'music-control')
    write_json(output/'preparation.json',dict(seconds=time.monotonic()-started,cases=len(CASES),original_source_consulted=False,tool_internal_changes=False))

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for n in ('original','environment_package','output'):p.add_argument(n,type=Path)
    a=p.parse_args();prepare(a.original.resolve(),a.environment_package.resolve(),a.output.resolve())
