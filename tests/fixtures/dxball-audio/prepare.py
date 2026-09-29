"""Prepare the real DX-Ball sound bank controller with independent providers."""
from spaghetti_extractor.components.comparison_wine_environment import wine_test_backend
import argparse
from pathlib import Path
import subprocess
import sys
import time
from spaghetti_extractor.components.comparison_environment import native_adapter_headers,native_environment,observation_headers
from spaghetti_extractor.components.comparison_original import native_entry_header
from spaghetti_extractor.components.comparison_package import prepare_comparison_package
from spaghetti_extractor.components.service_authoring import OperationDefinition,ServiceDefinition,component_interface,service_catalog
from spaghetti_extractor.util import sha256_file,write_json

HERE=Path(__file__).resolve().parent
PE_SHA256='191c113582e1f31016a158d40372fa21ea68d9348bf847bbfbc8e7c7bdfe195f'
RANGES=dict(suspend=(0x2f20,0x2f84),release_all=(0x2f90,0x2fa4),release_one=(0x2fb0,0x3000),
    play=(0x3210,0x32ab),loop=(0x32b0,0x334b),stop_all=(0x3350,0x3364),stop=(0x3370,0x33c4),
    restore=(0x33d0,0x345e),shutdown=(0x3460,0x346a))
EXTRAS={n:[('slot','u32'),('frequency','u32'),('pan','u32'),('volume','u32')] if n in ('play','loop') else
    [('slot','u32')] if n in ('stop','release_one') else [] for n in RANGES}
OP_PARAMETERS={n:[('state','audio_state'),('history','audio_history'),*p] for n,p in EXTRAS.items()}
ARGS=dict(frequency=[('buffer','audio_buffer'),('value','u32')],pan=[('buffer','audio_buffer'),('value','u32')],
    volume=[('buffer','audio_buffer'),('value','u32')],play=[('buffer','audio_buffer'),('flags','u32')],
    status=[('buffer','audio_buffer'),('status','audio_status')],restore_buffer=[('buffer','audio_buffer')],
    stop=[('buffer','audio_buffer')],position=[('buffer','audio_buffer'),('offset','u32')],
    release_buffer=[('buffer','audio_buffer')],release_device=[('device','audio_device')],
    free_sample=[('sample','audio_sample')],load_sample=[('slot','u32'),('name','audio_name')])
PARAMETERS={n:[('state','audio_state'),*p] for n,p in ARGS.items()}
RESULTS={n:'u32' if n in ('play','restore_buffer') else 'unit' for n in PARAMETERS}
NOMINALS={n:'dxball.audio.'+n.removeprefix('audio_') for n in ['audio_state','audio_history','audio_device','audio_buffer','audio_sample','audio_status','audio_name']}
TYPES=[dict(id='unit',kind='void'),dict(id='u32',kind='integer',width_bits=32,signed=False),*[dict(id=n,kind='opaque',nominal_id=v) for n,v in NOMINALS.items()]]
C_TYPES=dict(unit='void',u32='uint32_t',**{n:n+' *' for n in NOMINALS})
C_TYPES['audio_status']='audio_status_word *'
CASE_NAMES=['play-settings','play-zero-settings','loop-settings','play-lost-buffer','play-alternative-retry','loop-lost-buffer',
    'play-other-positive-result','play-no-device','play-empty-slot','stop','stop-lost-buffer','stop-unwritten-status',
    'restore-bank','restore-fails','restore-unwritten-history','restore-carried-status','release-one','release-without-device',
    'release-empty','release-without-buffer','release-redirected-record','free-redirects-slot','stop-redirected-buffer',
    'setting-redirected-buffer','restore-redirected-record','stop-all','release-all','suspend','suspend-without-device',
    'shutdown','connected-lifecycle','restore-without-device','retry-fails-again','release-primary-callback',
    'release-device-callback','last-slot-stop']
CASES=[dict(id=n,arguments=[str(i)]) for i,n in enumerate(CASE_NAMES)]

def bridge_spec():
    return dict(adapters={n:dict(symbol='audio_'+n,kind='portable',context=True,outcomes={'return':None}) for n in PARAMETERS},transports={},native_symbol=None)

def bridge():
    text='#include "portable-component-implementation.h"\n#include "audio-runtime.h"\n#include "comparison-service-bridge.h"\n'
    for i,n in enumerate(RANGES):
        text+='void fixture_audio_'+n+'('+','.join(C_TYPES[t]+' '+p for p,t in OP_PARAMETERS[n])+') {\n'
        text+=f'    audio_enter({i});spx_audio_bank_services_v5 services=spx_audio_bank_bind_services(NULL);\n    spx_audio_bank_context_v5 context={{0}};context.services=&services;spx_audio_bank_services_begin();\n'
        text+=f'    lifted_audio_{n}(&context,'+','.join(p for p,t in OP_PARAMETERS[n])+');spx_audio_bank_services_end();\n}\n'
    return text

def runtime_header():
    text='#ifndef DXBALL_AUDIO_RUNTIME_H\n#define DXBALL_AUDIO_RUNTIME_H\n#include "audio-state.h"\nvoid audio_enter(unsigned);\n'
    for n in RANGES:text+='void fixture_audio_'+n+'('+','.join(C_TYPES[t] for _,t in OP_PARAMETERS[n])+');\n'
    for n,p in PARAMETERS.items():text+=C_TYPES[RESULTS[n]]+' audio_'+n+'(void *'+''.join(', '+C_TYPES[t] for _,t in p)+');\n'
    return text+'enum { '+', '.join('AUDIO_SERVICE_'+n.upper()+'='+str(i) for i,n in enumerate(PARAMETERS))+' };\n#endif\n'

def prepare(original,output):
    started=time.monotonic();output.mkdir(parents=True,exist_ok=False)
    if sha256_file(original)!=PE_SHA256:raise ValueError('requires pinned DX-Ball PE32')
    services={n:ServiceDefinition.create(identity='dxball.audio.'+n,types=TYPES,parameters=p,result=RESULTS[n],
        resources=[],effects=['dxball.audio.'+n],outcomes=['return'],
        unobserved=['Shared slots, history, callback changes and provider lifetimes are checked by the observations in BOUNDARY.md; no checked heap summary is claimed.']) for n,p in PARAMETERS.items()}
    interface=component_interface(component_id='audio-bank',types=TYPES,services=services,
        operations={n:OperationDefinition(p,'unit',list(PARAMETERS)) for n,p in OP_PARAMETERS.items()})
    catalog=service_catalog(services).to_payload()
    write_json(output/'interface.json',interface.to_payload());write_json(output/'services.json',catalog);write_json(output/'bridge.json',bridge_spec())
    (output/'bridge.c').write_text(bridge());(output/'audio-runtime.h').write_text(runtime_header())
    sources={n:HERE/n for n in ('audio.c','audio-state.h')}
    args=['component','start','dxball','audio-bank','--interface-intent',str(output/'interface.json'),
        '--service-catalog',str(output/'services.json'),'--service-bridge',str(output/'bridge.json'),
        '--assumption-file',str(HERE/'BOUNDARY.md'),'--remove-source','source/component.c','--output',str(output/'authoring')]
    for n in RANGES:args+=['--operation-symbol',n+'=lifted_audio_'+n]
    for n,p in sources.items():args+=['--source-file','source/'+n+'='+str(p)]
    ran=subprocess.run([sys.executable,'-m','spaghetti_extractor',*args],capture_output=True,text=True)
    (output/'start.stdout').write_text(ran.stdout);(output/'start.stderr').write_text(ran.stderr)
    if ran.returncode:raise ValueError('inspect start.stderr')
    entries={**{'audio_'+n:r for n,r in RANGES.items()},'startup':(0xeaa0,0xeaa5),'audio_load':(0x3000,0x3008),'audio_free':(0xe2a0,0xe2a8)}
    (output/'native-image.h').write_text('\n'.join(native_entry_header(original=original,expected_sha256=PE_SHA256,module=None,
        entry_rva=lo,end_rva=hi,installer='install_'+n) for n,(lo,hi) in entries.items()))
    environment=native_environment()
    prepare_comparison_package(interface_package=output/'authoring/interface.json',source_files={n:output/'authoring/source'/n for n in sources},
        operation_symbols={n:'lifted_audio_'+n for n in RANGES},target_id='dxball',component_id='audio-bank',
        adapter_files={**wine_test_backend()['adapter_files'],'runtime.c':HERE/'runtime.c','bridge.c':output/'bridge.c'},
        include_files={**wine_test_backend()['include_files'],'native-image.h':output/'native-image.h','audio-runtime.h':output/'audio-runtime.h','audio-native.h':HERE/'audio-native.h',
            **native_adapter_headers('pe32-entry-hook.h'),**observation_headers()},
        **{**environment,'runtime_files':{**environment['runtime_files'],'DXBall.exe':original}},original_files=['runtime/DXBall.exe'],oracle_kind='native-original',
        cases=CASES,observation_fields=['audio'],assumptions=[(HERE/'BOUNDARY.md').read_text()],
        scope='Sound bank playback, loss recovery, disposal and device suspension through nine real entries; shared records, historical status and callbacks without game startup.',
        service_catalog=catalog,service_bridge=bridge_spec(),export_adapters=['adapters/bridge.c'],
        program_driver=dict(kind='pe32-import',image='runtime/DXBall.exe',library='dx-audio.dll',symbol='dx_audio_anchor'),output=output/'audio-bank')
    write_json(output/'preparation.json',dict(seconds=time.monotonic()-started,cases=len(CASES),original_source_consulted=False,tool_internal_changes=False))

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for n in ('original','output'):p.add_argument(n,type=Path)
    a=p.parse_args();prepare(a.original.resolve(),a.output.resolve())
