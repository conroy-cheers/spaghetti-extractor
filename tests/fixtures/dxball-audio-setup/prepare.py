"""Prepare sound device creation through the existing shared bank component."""
from spaghetti_extractor.components.comparison_wine_environment import wine_test_backend
import argparse
from pathlib import Path
import re
import subprocess
import sys
import time
from spaghetti_extractor.components.comparison_composition import bind_dependencies
from spaghetti_extractor.components.comparison_environment import native_environment
from spaghetti_extractor.components.comparison_original import native_entry_header
from spaghetti_extractor.components.comparison_package import prepare_comparison_package
from spaghetti_extractor.components.service_authoring import OperationDefinition,ServiceDefinition,component_interface,service_catalog
from spaghetti_extractor.util import sha256_file,write_json

HERE=Path(__file__).resolve().parent
PE_SHA256='191c113582e1f31016a158d40372fa21ea68d9348bf847bbfbc8e7c7bdfe195f'
RANGES=dict(initialize=(0x2c60,0x2c73),focus=(0x2c80,0x2f1b))
OP_PARAMETERS=[('state','audio_setup_state'),('window','shell_handle')]
ARGS=dict(release_all=[],create_device=[],cooperative=[('device','audio_device'),('window','shell_handle'),('level','u32')],
    create_primary=[('device','audio_device'),('spec','audio_buffer_spec')],play_primary=[('buffer','audio_buffer'),('flags','u32')],
    release_buffer=[('buffer','audio_buffer')],release_device=[('device','audio_device')],
    message=[('window','shell_handle'),('text','audio_name'),('caption','audio_name'),('flags','u32')],
    terminate=[('code','u32')],load_sample=[('slot','u32'),('name','audio_name')])
PARAMETERS={n:[('state','audio_setup_state'),*p] for n,p in ARGS.items()}
RESULTS={n:'u32' if n in ('create_device','cooperative','create_primary','play_primary','message') else 'unit' for n in PARAMETERS}
NOMINALS=dict(audio_setup_state='dxball.audio.setup',audio_buffer_spec='dxball.audio.buffer-spec',
    audio_device='dxball.audio.device',audio_buffer='dxball.audio.buffer',audio_name='dxball.audio.name',shell_handle='dxball.application.handle')
TYPES=[dict(id='unit',kind='void'),dict(id='u32',kind='integer',width_bits=32,signed=False),*[dict(id=n,kind='opaque',nominal_id=v) for n,v in NOMINALS.items()]]
C_TYPES=dict(unit='void',u32='uint32_t',**{n:n+' *' for n in NOMINALS})
CASE_NAMES=['already-initialized','focus-reloads-bank','create-continue','create-terminate','no-driver-continue','no-driver-terminate',
    'busy-retry','busy-ignore','busy-abort','graphics-create-failure','cooperative-continue','cooperative-terminate',
    'graphics-cooperative-failure','primary-unpublished-failure','primary-published-failure','primary-terminate','graphics-primary-failure',
    'play-continue','play-terminate','graphics-play-failure','create-callback-graphics','cooperative-callback-graphics',
    'primary-callback-device','release-primary-callback','release-device-callback','play-callback-slots','focus-empty-bank',
    'initialize-empty-device','initialize-existing-device','unexpected-dialog-result','busy-multiple-retries',
    'cooperative-positive-status','play-positive-status','create-positive-published','focus-then-initialize','suspend-refocus-initialize']
CASES=[dict(id=n,arguments=[str(i)]) for i,n in enumerate(CASE_NAMES)]

def bridge_spec():
    return dict(adapters={n:dict(symbol='setup_'+n,kind='portable',context=True,outcomes={'return':None}) for n in PARAMETERS},transports={},native_symbol=None)

def bridge():
    text='#include "portable-component-implementation.h"\n#include "setup-runtime.h"\n#include "comparison-service-bridge.h"\n'
    for i,n in enumerate(RANGES):
        text+='void fixture_setup_'+n+'('+','.join(C_TYPES[t]+' '+p for p,t in OP_PARAMETERS)+') {\n'
        text+=f'    setup_enter({i});spx_audio_setup_services_v5 services=spx_audio_setup_bind_services(NULL);\n    spx_audio_setup_context_v5 context={{0}};context.services=&services;spx_audio_setup_services_begin();\n'
        text+=f'    lifted_audio_{n}(&context,state,window);spx_audio_setup_services_end();\n}}\n'
    return text

def runtime_header():
    text='#ifndef DXBALL_AUDIO_SETUP_RUNTIME_H\n#define DXBALL_AUDIO_SETUP_RUNTIME_H\n#include "setup-state.h"\nvoid setup_enter(unsigned);\n'
    for n in RANGES:text+='void fixture_setup_'+n+'('+','.join(C_TYPES[t] for _,t in OP_PARAMETERS)+');\n'
    for n,p in PARAMETERS.items():text+=C_TYPES[RESULTS[n]]+' setup_'+n+'(void *'+''.join(', '+C_TYPES[t] for _,t in p)+');\n'
    return text+'enum { '+', '.join('SETUP_SERVICE_'+n.upper()+'='+str(i) for i,n in enumerate(PARAMETERS))+' };\n#endif\n'

def prepare(original,bank,shared,output):
    started=time.monotonic();output.mkdir(parents=True,exist_ok=False)
    if sha256_file(original)!=PE_SHA256:raise ValueError('requires pinned DX-Ball PE32')
    services={n:ServiceDefinition.create(identity='dxball.audio.setup.'+n,types=TYPES,parameters=p,result=RESULTS[n],
        resources=[],effects=['dxball.audio.setup.'+n],outcomes=['return'],nonlocal_outcomes=['process-exit'] if n=='terminate' else [],
        unobserved=['Shared bank/application ownership, callbacks and lifetimes in BOUNDARY.md; concrete composition, not checked heap summaries.']) for n,p in PARAMETERS.items()}
    interface=component_interface(component_id='audio-setup',types=TYPES,services=services,
        operations={n:OperationDefinition(OP_PARAMETERS,'unit',list(PARAMETERS)) for n in RANGES})
    catalog=service_catalog(services).to_payload()
    write_json(output/'interface.json',interface.to_payload());write_json(output/'services.json',catalog);write_json(output/'bridge.json',bridge_spec())
    (output/'bridge.c').write_text(bridge());(output/'setup-runtime.h').write_text(runtime_header())
    sources={n:HERE/n for n in ('setup.c','setup-state.h')};pending=['audio-state.h','shell-state.h']
    while pending:
        n=pending.pop()
        if n in sources:continue
        candidates=[bank/'source'/n,shared/'source'/n,*sorted((shared/'dependencies').glob('*/source/'+n))]
        p=next((p for p in candidates if p.is_file()),None)
        if p is None:raise ValueError('missing shared header '+n)
        sources[n]=p;pending+=re.findall(r'^#include "([^"]+)"',p.read_text(),re.MULTILINE)
    args=['component','start','dxball','audio-setup','--interface-intent',str(output/'interface.json'),
        '--service-catalog',str(output/'services.json'),'--service-bridge',str(output/'bridge.json'),
        '--assumption-file',str(HERE/'BOUNDARY.md'),'--remove-source','source/component.c','--output',str(output/'authoring')]
    for n in RANGES:args+=['--operation-symbol',n+'=lifted_audio_'+n]
    for n,p in sources.items():args+=['--source-file','source/'+n+'='+str(p)]
    ran=subprocess.run([sys.executable,'-m','spaghetti_extractor',*args],capture_output=True,text=True)
    (output/'start.stdout').write_text(ran.stdout);(output/'start.stderr').write_text(ran.stderr)
    if ran.returncode:raise ValueError('inspect start.stderr')
    entries={**{'setup_'+n:r for n,r in RANGES.items()},'setup_create_device':(0xdbe6,0xdbec),'setup_terminate':(0xe3d0,0xe3d8)}
    (output/'native-image.h').write_text((bank/'headers/native-image.h').read_text()+'\n'+'\n'.join(native_entry_header(
        original=original,expected_sha256=PE_SHA256,module=None,entry_rva=lo,end_rva=hi,installer='install_'+n) for n,(lo,hi) in entries.items()))
    headers={p.relative_to(bank/'headers').as_posix():p for p in (bank/'headers').rglob('*') if p.is_file()}
    headers.update({'native-image.h':output/'native-image.h','setup-runtime.h':output/'setup-runtime.h','bank-runtime.c':bank/'adapters/runtime.c'})
    environment=native_environment()
    prepare_comparison_package(interface_package=output/'authoring/interface.json',source_files={n:output/'authoring/source'/n for n in sources},
        operation_symbols={n:'lifted_audio_'+n for n in RANGES},target_id='dxball',component_id='audio-setup',
        adapter_files={**wine_test_backend()['adapter_files'],'runtime.c':HERE/'runtime.c','bridge.c':output/'bridge.c'},include_files={**headers,**wine_test_backend()['include_files']},
        **bind_dependencies(consumers={'shared-bank':bank}),
        **{**environment,'runtime_files':{**environment['runtime_files'],'DXBall.exe':original}},original_files=['runtime/DXBall.exe'],oracle_kind='native-original',
        cases=CASES,observation_fields=['audio_setup'],assumptions=[(HERE/'BOUNDARY.md').read_text()],
        scope='Complete sound initialize/focus bodies with real sound-bank disposal, shared application state, dialogs, finite retry schedules and process exit, without game startup.',
        service_catalog=catalog,service_bridge=bridge_spec(),export_adapters=['adapters/bridge.c'],
        program_driver=dict(kind='pe32-import',image='runtime/DXBall.exe',library='dx-audio-setup.dll',symbol='dx_audio_setup_anchor'),output=output/'audio-setup')
    write_json(output/'preparation.json',dict(seconds=time.monotonic()-started,cases=len(CASES),original_source_consulted=False,tool_internal_changes=False))

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for n in ('original','bank','shared','output'):p.add_argument(n,type=Path)
    a=p.parse_args();prepare(a.original.resolve(),a.bank.resolve(),a.shared.resolve(),a.output.resolve())
