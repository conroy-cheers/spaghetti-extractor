"""Prepare WAV loading and parsing against the pinned machine bodies."""
import argparse
from pathlib import Path
import subprocess
import sys
import time

from spaghetti_extractor.components.comparison_composition import bind_dependencies
from spaghetti_extractor.components.comparison_environment import native_environment
from spaghetti_extractor.components.comparison_original import native_entry_header
from spaghetti_extractor.components.comparison_package import prepare_comparison_package
from spaghetti_extractor.components.comparison_wine_environment import wine_test_backend
from spaghetti_extractor.components.service_authoring import OperationDefinition,ServiceDefinition,component_interface,service_catalog
from spaghetti_extractor.util import sha256_file,write_json

HERE=Path(__file__).resolve().parent
PE_SHA256='191c113582e1f31016a158d40372fa21ea68d9348bf847bbfbc8e7c7bdfe195f'
RANGES=dict(load=(0x3000,0x3204),parse=(0x3470,0x34ee))
OP_PARAMETERS=dict(load=[('state','audio_state'),('history','wave_history'),('slot','u32'),('name','audio_name')],
                   parse=[('file','wave_bytes'),('outputs','wave_result')])
PARAMETERS=dict(
    release_one=[('state','audio_state'),('slot','u32')],
    allocate=[('state','audio_state'),('bytes','u32')],
    terminate=[('code','u32')],
    read_file=[('state','audio_state'),('name','audio_name'),('offset','u32'),('owned','u32')],
    free_sample=[('state','audio_state'),('sample','audio_sample')],
    free_file=[('state','audio_state'),('file','wave_bytes')],
    create_buffer=[('state','audio_state'),('device','audio_device'),('sample','audio_sample'),('spec','wave_buffer_spec')],
    lock=[('state','audio_state'),('buffer','audio_buffer'),('length','u32'),('locked','wave_locked')],
    unlock=[('state','audio_state'),('buffer','audio_buffer'),('locked','wave_locked')],
    frequency=[('state','audio_state'),('buffer','audio_buffer'),('word','wave_word')],
    pan=[('state','audio_state'),('buffer','audio_buffer'),('word','wave_word')],
    volume=[('state','audio_state'),('buffer','audio_buffer'),('word','wave_word')])
RESULTS={n:dict(allocate='audio_sample',read_file='wave_bytes',create_buffer='u32',lock='u32').get(n,'unit') for n in PARAMETERS}
NOMINALS={**{n:'dxball.audio.'+n.removeprefix('audio_') for n in ('audio_state','audio_sample','audio_device','audio_buffer','audio_name')},
          **{n:'dxball.wave.'+n.removeprefix('wave_') for n in ('wave_bytes','wave_result','wave_history','wave_locked','wave_word','wave_buffer_spec')}}
TYPES=[dict(id='unit',kind='void'),dict(id='u32',kind='integer',width_bits=32,signed=False),
       *[dict(id=n,kind='opaque',nominal_id=v) for n,v in NOMINALS.items()]]
C_TYPES=dict(unit='void',u32='uint32_t',**{n:n+' *' for n in NOMINALS})
CASE_NAMES=['load','no-device','allocation-failure','file-failure','bad-riff','bad-wave','data-before-format',
    'empty-riff','short-format','fourteen-byte-format','duplicate-format','odd-unknown-chunk','format-without-data',
    'first-data-wins','create-failure','create-positive-status','create-failure-publishes','lock-failure',
    'lock-positive-status','ignored-unlock-failure','unwritten-frequency','partial-pan','failed-written-volume',
    'name-overwrites-metadata','frequency-redirects-record','pan-redirects-record','file-free-redirects-record',
    'file-read-redirects-record','create-redirects-device','create-redirects-record','lock-redirects-record',
    'load-twice','load-stop-release','second-data-ignored','multiple-unknown-chunks','later-short-format',
    'chunk-rounding-wrap']
PARSE_CASES=[0,4,5,6,7,8,9,10,11,12,13,33,34,35,36]
CASES=[dict(id=n,arguments=[str(i)]) for i,n in enumerate(CASE_NAMES)]+[
    dict(id='parse-'+CASE_NAMES[i],arguments=[str(100+i)]) for i in PARSE_CASES]

def bridge_spec():
    return dict(adapters={n:dict(symbol='wave_'+n,kind='portable',context=True,outcomes={'return':None}) for n in PARAMETERS},transports={},native_symbol=None)

def bridge():
    text='#include "portable-component-implementation.h"\n#include "wave-runtime.h"\n#include "comparison-service-bridge.h"\n'
    for i,n in enumerate(RANGES):
        result='uint32_t' if n=='parse' else 'void'
        text+=result+' fixture_wave_'+n+'('+','.join(C_TYPES[t]+' '+p for p,t in OP_PARAMETERS[n])+') {\n'
        text+=f'    wave_enter({i});spx_wave_loader_services_v5 services=spx_wave_loader_bind_services(NULL);\n    spx_wave_loader_context_v5 context={{0}};context.services=&services;spx_wave_loader_services_begin();\n'
        text+=('    uint32_t answer=' if n=='parse' else '    ')+f'lifted_wave_{n}(&context,'+','.join(p for p,t in OP_PARAMETERS[n])+');spx_wave_loader_services_end();\n'
        if n=='parse':text+='    return answer;\n'
        text+='}\n'
    return text

def runtime_header():
    text='#ifndef DXBALL_WAVE_RUNTIME_H\n#define DXBALL_WAVE_RUNTIME_H\n#include "wave-state.h"\nvoid wave_enter(unsigned);\n'
    for n in RANGES:text+=('uint32_t' if n=='parse' else 'void')+' fixture_wave_'+n+'('+','.join(C_TYPES[t] for _,t in OP_PARAMETERS[n])+');\n'
    for n,p in PARAMETERS.items():text+=C_TYPES[RESULTS[n]]+' wave_'+n+'(void *'+''.join(', '+C_TYPES[t] for _,t in p)+');\n'
    return text+'#endif\n'

def prepare(original,bank,output):
    started=time.monotonic();output.mkdir(parents=True,exist_ok=False)
    if sha256_file(original)!=PE_SHA256:raise ValueError('requires pinned DX-Ball PE32')
    services={n:ServiceDefinition.create(identity='dxball.wave.'+n,types=TYPES,parameters=p,result=RESULTS[n],
        resources=[],effects=['dxball.wave.'+n],outcomes=['return'],nonlocal_outcomes=['process-exit'] if n=='terminate' else [],
        unobserved=['Allocation identity, residual bytes, shared roots and historical outputs use the explicit mappings in BOUNDARY.md.']) for n,p in PARAMETERS.items()}
    interface=component_interface(component_id='wave-loader',types=TYPES,services=services,
        operations={n:OperationDefinition(p,'u32' if n=='parse' else 'unit',[] if n=='parse' else list(PARAMETERS)) for n,p in OP_PARAMETERS.items()})
    catalog=service_catalog(services).to_payload()
    write_json(output/'interface.json',interface.to_payload());write_json(output/'services.json',catalog);write_json(output/'bridge.json',bridge_spec())
    (output/'bridge.c').write_text(bridge());(output/'wave-runtime.h').write_text(runtime_header())
    sources={n:HERE/n for n in ('wave.c','wave-state.h')};sources['audio-state.h']=bank/'source/audio-state.h'
    args=['component','start','dxball','wave-loader','--interface-intent',str(output/'interface.json'),
        '--service-catalog',str(output/'services.json'),'--service-bridge',str(output/'bridge.json'),
        '--assumption-file',str(HERE/'BOUNDARY.md'),'--remove-source','source/component.c','--output',str(output/'authoring')]
    for n in RANGES:args+=['--operation-symbol',n+'=lifted_wave_'+n]
    for n,p in sources.items():args+=['--source-file','source/'+n+'='+str(p)]
    ran=subprocess.run([sys.executable,'-m','spaghetti_extractor',*args],capture_output=True,text=True)
    (output/'start.stdout').write_text(ran.stdout);(output/'start.stderr').write_text(ran.stderr)
    if ran.returncode:raise ValueError('inspect start.stderr')
    entries=dict(wave_allocate=(0xe2f0,0xe2f8),wave_file=(0xd9f0,0xd9f8),wave_terminate=(0xe3d0,0xe3d8),wave_parse=RANGES['parse'])
    (output/'native-image.h').write_text((bank/'headers/native-image.h').read_text()+'\n'+'\n'.join(native_entry_header(
        original=original,expected_sha256=PE_SHA256,module=None,entry_rva=lo,end_rva=hi,installer='install_'+n) for n,(lo,hi) in entries.items()))
    headers={p.relative_to(bank/'headers').as_posix():p for p in (bank/'headers').rglob('*') if p.is_file()}
    headers.update({'native-image.h':output/'native-image.h','wave-runtime.h':output/'wave-runtime.h','bank-runtime.c':bank/'adapters/runtime.c'})
    backend=wine_test_backend();environment=native_environment(bank)
    prepare_comparison_package(interface_package=output/'authoring/interface.json',source_files={n:output/'authoring/source'/n for n in sources},
        operation_symbols={n:'lifted_wave_'+n for n in RANGES},target_id='dxball',component_id='wave-loader',
        adapter_files={**backend['adapter_files'],'runtime.c':HERE/'runtime.c','bridge.c':output/'bridge.c'},include_files={**headers,**backend['include_files']},
        **bind_dependencies(consumers={'shared-bank':bank}),
        **{**environment,'runtime_files':{**environment['runtime_files'],'DXBall.exe':original}},original_files=['runtime/DXBall.exe'],oracle_kind='native-original',
        cases=CASES,observation_fields=['wave'],assumptions=[(HERE/'BOUNDARY.md').read_text()],
        scope='Complete WAV parsing and sample loading with shared sound-bank state, allocation and partial failure outputs, without starting the game.',
        service_catalog=catalog,service_bridge=bridge_spec(),export_adapters=['adapters/bridge.c'],
        program_driver=dict(kind='pe32-import',image='runtime/DXBall.exe',library='dx-wave.dll',symbol='dx_wave_anchor'),output=output/'wave-loader')
    write_json(output/'preparation.json',dict(seconds=time.monotonic()-started,cases=len(CASES),original_source_consulted=False,tool_internal_changes=False))

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for n in ('original','bank','output'):p.add_argument(n,type=Path)
    a=p.parse_args();prepare(a.original.resolve(),a.bank.resolve(),a.output.resolve())
