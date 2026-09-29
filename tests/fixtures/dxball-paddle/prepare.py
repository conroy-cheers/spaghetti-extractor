"""Prepare the actual paddle movement and drawing entries through shared object views."""
import argparse
from pathlib import Path
import re
import subprocess
import sys
import time
from spaghetti_extractor.components.comparison_environment import native_adapter_headers, native_environment, observation_headers
from spaghetti_extractor.components.comparison_original import native_entry_header
from spaghetti_extractor.components.comparison_package import prepare_comparison_package
from spaghetti_extractor.components.service_authoring import OperationDefinition, ServiceDefinition, component_interface, service_catalog
from spaghetti_extractor.util import sha256_file, write_json

HERE=Path(__file__).resolve().parent
PE_SHA256='191c113582e1f31016a158d40372fa21ea68d9348bf847bbfbc8e7c7bdfe195f'
RANGES=dict(move=(0x6730,0x67a7),draw=(0x67b0,0x69b3))
OP_ARGS={name:[] for name in RANGES}
HOOKS=dict(elapsed=0xdb80,now=0xdb20,random=0xae20,damage=0x1200,sprite=0x1080)
PARAMETERS=dict(cursor=[('state','paddle_state'),('x','u32'),('y','u32')],
    elapsed=[('state','paddle_state'),('previous','u32'),('delay','u32')],now=[('state','paddle_state')],clock=[('state','paddle_state')],
    random=[('state','paddle_state'),('limit','u32')],
    blit_fast=[('state','paddle_state'),('destination','cleanup_surface'),('x','u32'),('y','u32'),('source','cleanup_surface'),('bounds','font_rect'),('flags','u32')],
    damage=[('state','paddle_state'),('bounds','font_rect')],sprite=[('state','paddle_state'),('slot','u32'),('x','u32'),('y','u32')])
RESULTS={name:'u32' if name in ('elapsed','now','clock','random') else 'unit' for name in PARAMETERS}
TYPES=[dict(id='unit',kind='void'),dict(id='u32',kind='integer',width_bits=32,signed=False),
    *[dict(id=name,kind='opaque',nominal_id=nominal) for name,nominal in [('paddle_state','dxball.paddle.state'),
        ('font_rect','dxball.font.rect'),('cleanup_surface','dxball.cleanup.surface')]]]
C_TYPES=dict(unit='void',u32='uint32_t',paddle_state='paddle_state *',font_rect='font_rect *',cleanup_surface='font_surface *')
CASE_NAMES=['movement-clamps','windowed-movement','signed-widths','cursor-callback','ordinary-draw','phase-advance',
    'gun-draw','changed-draw','changed-gun','spark-deadlines','all-random-choices','crop-rounding',
    'elapsed-callback','now-callback','clock-callback','random-callback','second-clock-callback',
    'blit-callback','damage-callback','shared-bank-aliases','movement-draw-sequence']

def bridge_spec():
    return dict(adapters={name:dict(symbol='paddle_'+name,kind='portable',context=True,outcomes={'return':None}) for name in PARAMETERS},transports={},native_symbol=None)

def bridge():
    text='#include "portable-component-implementation.h"\n#include "paddle-runtime.h"\n#include "comparison-service-bridge.h"\n'
    for i,name in enumerate(RANGES):
        params=''.join(',uint32_t '+arg for arg in OP_ARGS[name]);args=''.join(','+arg for arg in OP_ARGS[name])
        text+=f'void fixture_paddle_{name}(paddle_state *state{params}) {{\n    paddle_enter({i}); spx_paddle_control_services_v5 services=spx_paddle_control_bind_services(NULL);\n    spx_paddle_control_context_v5 context={{0}}; context.services=&services; spx_paddle_control_services_begin();\n'
        text+=f'    lifted_paddle_{name}(&context,state{args}); spx_paddle_control_services_end();\n}}\n'
    return text

def runtime_header():
    text='#ifndef DXBALL_PADDLE_RUNTIME_H\n#define DXBALL_PADDLE_RUNTIME_H\n#include "paddle-state.h"\nvoid paddle_enter(unsigned);\n'
    for name in RANGES:text+='void fixture_paddle_'+name+'(paddle_state *'+',uint32_t'*len(OP_ARGS[name])+');\n'
    for name,params in PARAMETERS.items():text+=C_TYPES[RESULTS[name]]+' paddle_'+name+'(void *'+''.join(', '+C_TYPES[t] for _,t in params)+');\n'
    return text+'enum { '+', '.join('PADDLE_'+name.upper()+'='+str(i) for i,name in enumerate(PARAMETERS))+' };\n#endif\n'

def prepare(original,shared_package,output):
    start=time.monotonic()
    if sha256_file(original)!=PE_SHA256:raise ValueError('requires pinned DX-Ball PE32')
    output.mkdir(parents=True,exist_ok=False)
    services={name:ServiceDefinition.create(identity='dxball.paddle.'+name,types=TYPES,parameters=params,result=RESULTS[name],
        resources=[],effects=['dxball.paddle.'+name],outcomes=['return'],unobserved=['Shared storage and ordered service effects in BOUNDARY.md; concrete comparisons, not checked heap summaries.']) for name,params in PARAMETERS.items()}
    interface=component_interface(component_id='paddle-control',types=TYPES,services=services,
        operations={name:OperationDefinition([('state','paddle_state')]+[(arg,'u32') for arg in OP_ARGS[name]],'unit',list(PARAMETERS)) for name in RANGES})
    catalog=service_catalog(services).to_payload()
    write_json(output/'interface.json',interface.to_payload());write_json(output/'services.json',catalog);write_json(output/'bridge.json',bridge_spec())
    (output/'bridge.c').write_text(bridge());(output/'paddle-runtime.h').write_text(runtime_header())
    sources={'paddle.c':HERE/'paddle.c','paddle-state.h':HERE/'paddle-state.h'};pending=['pickup-state.h']
    while pending:
        name=pending.pop()
        if name in sources:continue
        path=shared_package/'source'/name
        if not path.is_file():raise ValueError('missing shared header '+name)
        sources[name]=path;pending+=re.findall(r'^#include "([^"]+)"',path.read_text(),re.MULTILINE)
    args=['component','start','dxball','paddle-control','--interface-intent',str(output/'interface.json'),'--service-catalog',str(output/'services.json'),
        '--service-bridge',str(output/'bridge.json'),'--assumption-file',str(HERE/'BOUNDARY.md'),'--remove-source','source/component.c','--output',str(output/'authoring')]
    for name in RANGES:args+=['--operation-symbol',name+'=lifted_paddle_'+name]
    for name,path in sources.items():args+=['--source-file','source/'+name+'='+str(path)]
    ran=subprocess.run([sys.executable,'-m','spaghetti_extractor',*args],capture_output=True,text=True)
    (output/'start.stdout').write_text(ran.stdout);(output/'start.stderr').write_text(ran.stderr)
    if ran.returncode:raise RuntimeError('inspect '+str(output/'start.stderr'))
    entries={**{'paddle_'+n:r for n,r in RANGES.items()},'startup':(0xeaa0,0xeaa5),**{'paddle_service_'+n:(r,r+8) for n,r in HOOKS.items()}}
    (output/'native-image.h').write_text('\n'.join(native_entry_header(original=original,expected_sha256=PE_SHA256,module=None,entry_rva=lo,end_rva=hi,installer='install_'+n) for n,(lo,hi) in entries.items()))
    environment=native_environment()
    prepare_comparison_package(interface_package=output/'authoring/interface.json',source_files={n:output/'authoring/source'/n for n in sources},
        operation_symbols={n:'lifted_paddle_'+n for n in RANGES},target_id='dxball',component_id='paddle-control',
        adapter_files={'runtime.c':HERE/'runtime.c','bridge.c':output/'bridge.c'},
        include_files={'native-image.h':output/'native-image.h','paddle-runtime.h':output/'paddle-runtime.h',
            'play-native.h':HERE.parent/'dxball-gameplay/play-native.h','motion-native.h':HERE.parent/'dxball-ball-motion/motion-native.h',
            **native_adapter_headers('pe32-entry-hook.h'),**observation_headers()},
        **{**environment,'runtime_files':{**environment['runtime_files'],'DXBall.exe':original}},original_files=['runtime/DXBall.exe'],oracle_kind='native-original',
        cases=[dict(id=n,arguments=[str(i)]) for i,n in enumerate(CASE_NAMES)],observation_fields=['paddles'],
        assumptions=[(HERE/'BOUNDARY.md').read_text()],scope='Actual paddle movement and drawing over shared gameplay, input, sprite and surface state without application startup.',
        service_catalog=catalog,service_bridge=bridge_spec(),export_adapters=['adapters/bridge.c'],
        program_driver=dict(kind='pe32-import',image='runtime/DXBall.exe',library='dx-paddles.dll',symbol='dx_paddles_anchor'),output=output/'paddle-control')
    write_json(output/'preparation.json',dict(seconds=time.monotonic()-start,cases=len(CASE_NAMES),original_source_consulted=False,tool_internal_changes=False))

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('original','shared_package','output'):p.add_argument(name,type=Path)
    a=p.parse_args();prepare(a.original.resolve(),a.shared_package.resolve(),a.output.resolve())
