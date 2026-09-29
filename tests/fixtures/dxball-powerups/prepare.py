"""Prepare seven powerup actions over existing shared objects and temporary lists."""
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
RANGES=dict(split=(0x7eb0,0x8253),expand=(0x8260,0x84a1),soften=(0x84b0,0x8538),
    detonate=(0x8540,0x857a),super=(0x8580,0x85c3),drop=(0x85d0,0x86d3),release=(0x86e0,0x8736))
HOOKS=dict(allocate=0xdf40,free=0xdf30,terminate=0xe3d0,destination=0xbd60,cell=0x5ad0,
    hit=0x5c80,rebound=0x5710,stop_sound=0x3370,play_sound=0x3210,damage=0x1350)
PARAMETERS={name:[('state','powerup_state')] for name in ('allocate_ball','allocate_cell','rebound')}
PARAMETERS.update(free_ball=[('state','powerup_state'),('ball','play_ball')],
    free_cell=[('state','powerup_state'),('cell','play_event')],terminate=[('state','powerup_state'),('status','u32')],
    destination=[('state','powerup_state'),('surface','cleanup_surface')],
    cell=[('state','powerup_state'),('column','u32'),('row','u32'),('mode','u32')],
    hit=[('state','powerup_state'),('column','u32'),('row','u32')],
    stop_sound=[('state','powerup_state'),('sound','u32')],
    play_sound=[('state','powerup_state'),('sound','u32'),('repeat','u32'),('volume','u32'),('pan','u32')],
    blit=[('state','powerup_state'),('destination','cleanup_surface'),('destination_bounds','font_rect'),
          ('source','cleanup_surface'),('source_bounds','font_rect'),('flags','u32')],
    damage=[('state','powerup_state'),('bounds','font_rect')])
RESULTS={name:'play_ball' if name=='allocate_ball' else 'play_event' if name=='allocate_cell' else 'u32' if name=='hit' else 'unit' for name in PARAMETERS}
TYPES=[dict(id='unit',kind='void'),dict(id='u32',kind='integer',width_bits=32,signed=False),
    *[dict(id=name,kind='opaque',nominal_id=nominal) for name,nominal in (
        ('powerup_state','dxball.powerup.state'),('play_ball','dxball.play.ball'),('play_event','dxball.play.event'),
        ('cleanup_surface','dxball.cleanup.surface'),('font_rect','dxball.font.rect'))]]
C_TYPES=dict(unit='void',u32='uint32_t',powerup_state='powerup_state *',play_ball='play_ball *',play_event='play_event *',cleanup_surface='font_surface *',font_rect='font_rect *')
CASE_NAMES=['empty-actions','split-one','split-attached-speeds','split-existing-staging','split-allocation-callback',
    'split-free-callback','split-failure-staging','split-failure-live','expand-empty','expand-center','expand-corners',
    'expand-existing-queue','expand-allocation-callback','expand-graphics-callback','expand-free-callback',
    'soften-kinds','soften-repeated-callback','destination-callback','detonate-results','detonate-callback',
    'super-balls','drop-empty','drop-cascade','drop-bottom','drop-blit-alias-callback','drop-cell-callback',
    'release-attached','release-callback','generated-sequence','drop-sound-callback']

def bridge_spec():
    return dict(adapters={name:dict(symbol='power_'+name,kind='portable',context=True,outcomes={'return':None}) for name in PARAMETERS},transports={},native_symbol=None)

def bridge():
    text='#include "portable-component-implementation.h"\n#include "power-runtime.h"\n#include "comparison-service-bridge.h"\n'
    for i,name in enumerate(RANGES):
        text+=f'void fixture_power_{name}(powerup_state *state) {{\n    power_enter({i}); spx_powerup_actions_services_v5 services=spx_powerup_actions_bind_services(NULL);\n    spx_powerup_actions_context_v5 context={{0}}; context.services=&services; spx_powerup_actions_services_begin();\n    lifted_power_{name}(&context,state); spx_powerup_actions_services_end();\n}}\n'
    return text

def runtime_header():
    text='#ifndef DXBALL_POWER_RUNTIME_H\n#define DXBALL_POWER_RUNTIME_H\n#include "power-state.h"\nvoid power_enter(unsigned);\n'
    for name in RANGES:text+='void fixture_power_'+name+'(powerup_state *);\n'
    for name,params in PARAMETERS.items():text+=C_TYPES[RESULTS[name]]+' power_'+name+'(void *'+''.join(', '+C_TYPES[t] for _,t in params)+');\n'
    return text+'enum { '+', '.join('POWER_'+name.upper()+'='+str(i) for i,name in enumerate(PARAMETERS))+' };\n#endif\n'

def prepare(original,shared_package,output):
    start=time.monotonic()
    if sha256_file(original)!=PE_SHA256:raise ValueError('requires pinned DX-Ball PE32')
    output.mkdir(parents=True,exist_ok=False)
    services={name:ServiceDefinition.create(identity='dxball.powerup.'+name,types=TYPES,parameters=params,result=RESULTS[name],
        resources=[],effects=['dxball.powerup.'+name],outcomes=['return'],
        unobserved=['Existing shared objects and temporary list/lifetime contract in BOUNDARY.md; concrete comparisons, not checked summaries.']) for name,params in PARAMETERS.items()}
    interface=component_interface(component_id='powerup-actions',types=TYPES,services=services,
        operations={name:OperationDefinition([('state','powerup_state')],'unit',list(PARAMETERS)) for name in RANGES})
    catalog=service_catalog(services).to_payload()
    write_json(output/'interface.json',interface.to_payload());write_json(output/'services.json',catalog);write_json(output/'bridge.json',bridge_spec())
    (output/'bridge.c').write_text(bridge());(output/'power-runtime.h').write_text(runtime_header())
    sources={'power.c':HERE/'power.c','power-state.h':HERE/'power-state.h'};pending=['motion-state.h']
    while pending:
        name=pending.pop()
        if name in sources:continue
        path=shared_package/'source'/name
        if not path.is_file():raise ValueError('missing shared header '+name)
        sources[name]=path;pending+=re.findall(r'^#include "([^\"]+)"',path.read_text(),re.MULTILINE)
    args=['component','start','dxball','powerup-actions','--interface-intent',str(output/'interface.json'),'--service-catalog',str(output/'services.json'),
        '--service-bridge',str(output/'bridge.json'),'--assumption-file',str(HERE/'BOUNDARY.md'),'--remove-source','source/component.c','--output',str(output/'authoring')]
    for name in RANGES:args+=['--operation-symbol',name+'=lifted_power_'+name]
    for name,path in sources.items():args+=['--source-file','source/'+name+'='+str(path)]
    ran=subprocess.run([sys.executable,'-m','spaghetti_extractor',*args],capture_output=True,text=True)
    (output/'start.stdout').write_text(ran.stdout);(output/'start.stderr').write_text(ran.stderr)
    if ran.returncode:raise RuntimeError('inspect '+str(output/'start.stderr'))
    entries={**{'power_'+n:r for n,r in RANGES.items()},'startup':(0xeaa0,0xeaa5),**{'power_service_'+n:(r,r+8) for n,r in HOOKS.items()}}
    (output/'native-image.h').write_text('\n'.join(native_entry_header(original=original,expected_sha256=PE_SHA256,module=None,entry_rva=lo,end_rva=hi,installer='install_'+name) for name,(lo,hi) in entries.items()))
    environment=native_environment()
    prepare_comparison_package(interface_package=output/'authoring/interface.json',source_files={n:output/'authoring/source'/n for n in sources},
        operation_symbols={n:'lifted_power_'+n for n in RANGES},target_id='dxball',component_id='powerup-actions',
        adapter_files={'runtime.c':HERE/'runtime.c','bridge.c':output/'bridge.c'},
        include_files={'native-image.h':output/'native-image.h','power-runtime.h':output/'power-runtime.h',
            'play-native.h':HERE.parent/'dxball-gameplay/play-native.h','motion-native.h':HERE.parent/'dxball-ball-motion/motion-native.h',
            **native_adapter_headers('pe32-entry-hook.h'),**observation_headers()},
        **{**environment,'runtime_files':{**environment['runtime_files'],'DXBall.exe':original}},original_files=['runtime/DXBall.exe'],oracle_kind='native-original',
        cases=[dict(id=n,arguments=[str(i)]) for i,n in enumerate(CASE_NAMES)],observation_fields=['powerups'],
        assumptions=[(HERE/'BOUNDARY.md').read_text()],scope='Seven actual powerup entries over shared objects, mutable services and temporary lists without game startup.',
        service_catalog=catalog,service_bridge=bridge_spec(),export_adapters=['adapters/bridge.c'],
        program_driver=dict(kind='pe32-import',image='runtime/DXBall.exe',library='dx-power.dll',symbol='dx_power_anchor'),output=output/'powerup-actions')
    write_json(output/'preparation.json',dict(seconds=time.monotonic()-start,cases=len(CASE_NAMES),original_source_consulted=False,tool_internal_changes=False))

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('original','shared_package','output'):p.add_argument(name,type=Path)
    a=p.parse_args();prepare(a.original.resolve(),a.shared_package.resolve(),a.output.resolve())
