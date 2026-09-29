"""Prepare the actual shot lifecycle through existing gameplay and motion views."""
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
RANGES=dict(update=(0x69c0,0x6aeb),fire=(0x6af0,0x6cb3),remove=(0x6cc0,0x6d26))
OP_ARGS={name:[] for name in RANGES}
HOOKS=dict(allocate=0xdf40,free=0xdf30,terminate=0xe3d0,random=0xae20,hit=0x5c80,stop_sound=0x3370,pan=0x3550,play_sound=0x3210)
PARAMETERS={name:[('state','ball_motion_state')] for name in HOOKS}
PARAMETERS.update(free=[('state','ball_motion_state'),('storage','allocation')],terminate=[('state','ball_motion_state'),('status','u32')],
    random=[('state','ball_motion_state'),('limit','u32')],hit=[('state','ball_motion_state'),('column','u32'),('row','u32')],
    stop_sound=[('state','ball_motion_state'),('sound','u32')],pan=[('state','ball_motion_state'),('x','u32')],
    play_sound=[('state','ball_motion_state'),('sound','u32'),('repeat','u32'),('pan','u32'),('flags','u32')])
RESULTS={name:'allocation' if name=='allocate' else 'u32' if name in ('random','hit','pan') else 'unit' for name in HOOKS}
TYPES=[dict(id='unit',kind='void'),dict(id='u32',kind='integer',width_bits=32,signed=False),
    dict(id='ball_motion_state',kind='opaque',nominal_id='dxball.motion.state'),
    dict(id='allocation',kind='opaque',nominal_id='portable.heap.storage')]
C_TYPES=dict(unit='void',u32='uint32_t',ball_motion_state='motion_state *',allocation='struct spx_opaque_allocation_v5 *')
CASE_NAMES=['empty-update','fire-empty','fire-tail','fire-rounding','first-allocation-callback','second-allocation-callback',
    'stop-sound-callback','pan-callback','play-sound-callback','allocation-failure-call','remove-null','remove-single',
    'remove-head','remove-middle','remove-tail','free-callback','flight','above-board','below-board','ceiling-removal',
    'brick-hit','brick-no-score','piercing-hit','skipped-successor','random-callback','hit-callback','all-random-choices',
    'linear-board-alias','bank-alias','fire-move-expire']

def bridge_spec():
    return dict(adapters={name:dict(symbol='shot_'+name,kind='portable',context=True,outcomes={'return':None}) for name in PARAMETERS},transports={},native_symbol=None)

def bridge():
    text='#include "portable-component-implementation.h"\n#include "shot-runtime.h"\n#include "comparison-service-bridge.h"\n'
    for i,name in enumerate(RANGES):
        params=''.join(',uint32_t '+arg for arg in OP_ARGS[name]);args=''.join(','+arg for arg in OP_ARGS[name])
        text+=f'void fixture_shot_{name}(motion_state *state{params}) {{\n    shot_enter({i}); spx_shot_lifecycle_services_v5 services=spx_shot_lifecycle_bind_services(NULL);\n    spx_shot_lifecycle_context_v5 context={{0}}; context.services=&services; spx_shot_lifecycle_services_begin();\n'
        text+=f'    lifted_shot_{name}(&context,state{args}); spx_shot_lifecycle_services_end();\n}}\n'
    return text

def runtime_header():
    text='#ifndef DXBALL_SHOT_RUNTIME_H\n#define DXBALL_SHOT_RUNTIME_H\n#include "motion-state.h"\nstruct spx_opaque_allocation_v5;\nvoid shot_enter(unsigned);\n'
    for name in RANGES:text+='void fixture_shot_'+name+'(motion_state *'+',uint32_t'*len(OP_ARGS[name])+');\n'
    for name,params in PARAMETERS.items():text+=C_TYPES[RESULTS[name]]+' shot_'+name+'(void *'+''.join(', '+C_TYPES[t] for _,t in params)+');\n'
    return text+'enum { '+', '.join('SHOT_'+name.upper()+'='+str(i) for i,name in enumerate(PARAMETERS))+' };\n#endif\n'

def prepare(original,shared_package,output):
    start=time.monotonic()
    if sha256_file(original)!=PE_SHA256:raise ValueError('requires pinned DX-Ball PE32')
    output.mkdir(parents=True,exist_ok=False)
    services={name:ServiceDefinition.create(identity='dxball.shot.'+name,types=TYPES,parameters=params,result=RESULTS[name],
        resources=[],effects=['dxball.shot.'+name],outcomes=['return'],unobserved=['Shared shot storage, allocation identity and ordered service effects in BOUNDARY.md; concrete comparisons, not checked heap summaries.']) for name,params in PARAMETERS.items()}
    interface=component_interface(component_id='shot-lifecycle',types=TYPES,services=services,
        operations={name:OperationDefinition([('state','ball_motion_state')]+[(arg,'u32') for arg in OP_ARGS[name]],'unit',list(PARAMETERS)) for name in RANGES})
    catalog=service_catalog(services).to_payload()
    write_json(output/'interface.json',interface.to_payload());write_json(output/'services.json',catalog);write_json(output/'bridge.json',bridge_spec())
    (output/'bridge.c').write_text(bridge());(output/'shot-runtime.h').write_text(runtime_header())
    sources={'shot.c':HERE/'shot.c','motion-state.h':HERE.parent/'dxball-ball-motion/motion-state.h'};pending=['play-state.h','board-state.h']
    while pending:
        name=pending.pop()
        if name in sources:continue
        path=shared_package/'source'/name
        if not path.is_file():raise ValueError('missing shared header '+name)
        sources[name]=path;pending+=re.findall(r'^#include "([^"]+)"',path.read_text(),re.MULTILINE)
    args=['component','start','dxball','shot-lifecycle','--interface-intent',str(output/'interface.json'),'--service-catalog',str(output/'services.json'),
        '--service-bridge',str(output/'bridge.json'),'--assumption-file',str(HERE/'BOUNDARY.md'),'--remove-source','source/component.c','--output',str(output/'authoring')]
    for name in RANGES:args+=['--operation-symbol',name+'=lifted_shot_'+name]
    for name,path in sources.items():args+=['--source-file','source/'+name+'='+str(path)]
    ran=subprocess.run([sys.executable,'-m','spaghetti_extractor',*args],capture_output=True,text=True)
    (output/'start.stdout').write_text(ran.stdout);(output/'start.stderr').write_text(ran.stderr)
    if ran.returncode:raise RuntimeError('inspect '+str(output/'start.stderr'))
    entries={**{'shot_'+n:r for n,r in RANGES.items()},'startup':(0xeaa0,0xeaa5),**{'shot_service_'+n:(r,r+8) for n,r in HOOKS.items()}}
    (output/'native-image.h').write_text('\n'.join(native_entry_header(original=original,expected_sha256=PE_SHA256,module=None,entry_rva=lo,end_rva=hi,installer='install_'+n) for n,(lo,hi) in entries.items()))
    environment=native_environment()
    prepare_comparison_package(interface_package=output/'authoring/interface.json',source_files={n:output/'authoring/source'/n for n in sources},
        operation_symbols={n:'lifted_shot_'+n for n in RANGES},target_id='dxball',component_id='shot-lifecycle',
        adapter_files={'runtime.c':HERE/'runtime.c','bridge.c':output/'bridge.c'},
        include_files={'native-image.h':output/'native-image.h','shot-runtime.h':output/'shot-runtime.h',
            'play-native.h':HERE.parent/'dxball-gameplay/play-native.h','motion-native.h':HERE.parent/'dxball-ball-motion/motion-native.h',
            **native_adapter_headers('pe32-entry-hook.h'),**observation_headers()},
        **{**environment,'runtime_files':{**environment['runtime_files'],'DXBall.exe':original}},original_files=['runtime/DXBall.exe'],oracle_kind='native-original',
        cases=[dict(id=n,arguments=[str(i)]) for i,n in enumerate(CASE_NAMES)],observation_fields=['shots'],
        assumptions=[(HERE/'BOUNDARY.md').read_text()],scope='Actual three-entry shot lifecycle over shared shot records, board and sprite views, without application startup.',
        service_catalog=catalog,service_bridge=bridge_spec(),export_adapters=['adapters/bridge.c'],
        program_driver=dict(kind='pe32-import',image='runtime/DXBall.exe',library='dx-shots.dll',symbol='dx_shots_anchor'),output=output/'shot-lifecycle')
    write_json(output/'preparation.json',dict(seconds=time.monotonic()-start,cases=len(CASE_NAMES),original_source_consulted=False,tool_internal_changes=False))

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('original','shared_package','output'):p.add_argument(name,type=Path)
    a=p.parse_args();prepare(a.original.resolve(),a.shared_package.resolve(),a.output.resolve())
