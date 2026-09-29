"""Prepare gameplay progression over existing shared objects and service boundaries."""
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
RANGES=dict(refresh=(0x8740,0x8770),draw=(0x8770,0x88f1),count=(0x8900,0x892c),next=(0x8930,0x898e),
    lose=(0x8990,0x89d9),over=(0x89e0,0x89ff),restart=(0x8a00,0x8b35),advance=(0x8b40,0x8c15))
HOOKS=dict(destination=0xbd60,text=0xc6b0,damage=0x1350,sprite=0xbd90,load_board=0x5a70,
    stop_sound=0x3370,pan=0x3550,play_sound=0x3210,wait=0x2240,redraw=0xaad0,palette=0x23e0,
    fade=0x2770,create_ball=0x4d70,clear=0x2710,clear_objects=0x8fd0,reset_damage=0x1000)
PARAMETERS={name:[('state','progression_state')] for name in ('load_board','redraw','create_ball','clear_objects','reset_damage')}
PARAMETERS.update(
    blit_fast=[('state','progression_state'),('destination','cleanup_surface'),('x','u32'),('y','u32'),('source','cleanup_surface'),('bounds','font_rect'),('flags','u32')],
    destination=[('state','progression_state'),('surface','cleanup_surface')],
    text=[('state','progression_state'),('x','u32'),('y','u32'),('length','u32'),('bytes','font_bytes')],
    damage=[('state','progression_state'),('bounds','font_rect')],
    sprite=[('state','progression_state'),('slot','u32'),('x','u32'),('y','u32')],
    stop_sound=[('state','progression_state'),('sound','u32')],pan=[('state','progression_state'),('x','u32')],
    play_sound=[('state','progression_state'),('a','u32'),('b','u32'),('c','u32'),('d','u32')],
    wait=[('state','progression_state'),('count','u32')],palette=[('state','progression_state'),('name','asset_name')],
    fade=[('state','progression_state'),('wait','u32'),('step','u32'),('first','u32'),('last','u32'),('direction','u32')],
    clear=[('state','progression_state'),('surface','cleanup_surface'),('color','u32')])
RESULTS={name:'u32' if name=='pan' else 'unit' for name in PARAMETERS}
TYPES=[dict(id='unit',kind='void'),dict(id='u32',kind='integer',width_bits=32,signed=False),
    *[dict(id=name,kind='opaque',nominal_id=nominal) for name,nominal in (
        ('progression_state','dxball.progression.state'),('cleanup_surface','dxball.cleanup.surface'),
        ('font_rect','dxball.font.rect'),('font_bytes','dxball.font.bytes'),('asset_name','dxball.asset.name'))]]
C_TYPES=dict(unit='void',u32='uint32_t',progression_state='progression_state *',cleanup_surface='font_surface *',font_rect='font_rect *',font_bytes='font_bytes *',asset_name='asset_name *')
CASE_NAMES=['cached-score','refresh-score','refresh-overflow','cached-overflow','unsigned-score-text',
    'negative-lives','clamped-lives','drawing-callbacks','count-empty','count-all-byte-values','count-unbreakable',
    'next-board','next-empty-board','past-last-board','past-last-empty-board','board-index-wrap',
    'lose-life','lose-wrapping-life','loss-callbacks','game-over-callback','restart-round','restart-negative-width',
    'restart-callbacks','inactive-transition','pending-value-two','lost-life-transition','new-board-transition',
    'last-life-transition','score-scene-transition','cleanup-callback','fade-callback','damage-reset-callback','round-sequence']

def bridge_spec():
    return dict(adapters={name:dict(symbol='progress_'+name,kind='portable',context=True,outcomes={'return':None}) for name in PARAMETERS},transports={},native_symbol=None)

def bridge():
    text='#include "portable-component-implementation.h"\n#include "progress-runtime.h"\n#include "comparison-service-bridge.h"\n'
    for i,name in enumerate(RANGES):
        result='uint32_t' if name=='count' else 'void'
        call=('uint32_t result=' if name=='count' else '')+f'lifted_progress_{name}(&context,state);'
        text+=f'{result} fixture_progress_{name}(progression_state *state) {{\n    progress_enter({i}); spx_gameplay_progression_services_v5 services=spx_gameplay_progression_bind_services(NULL);\n    spx_gameplay_progression_context_v5 context={{0}}; context.services=&services; spx_gameplay_progression_services_begin();\n    {call} spx_gameplay_progression_services_end();'+(' return result;' if name=='count' else '')+'\n}\n'
    return text

def runtime_header():
    text='#ifndef DXBALL_PROGRESS_RUNTIME_H\n#define DXBALL_PROGRESS_RUNTIME_H\n#include "progression-state.h"\nvoid progress_enter(unsigned);\n'
    for name in RANGES:text+=('uint32_t' if name=='count' else 'void')+' fixture_progress_'+name+'(progression_state *);\n'
    for name,params in PARAMETERS.items():text+=C_TYPES[RESULTS[name]]+' progress_'+name+'(void *'+''.join(', '+C_TYPES[t] for _,t in params)+');\n'
    return text+'enum { '+', '.join('PROGRESS_'+name.upper()+'='+str(i) for i,name in enumerate(PARAMETERS))+' };\n#endif\n'

def prepare(original,shared_package,output):
    start=time.monotonic()
    if sha256_file(original)!=PE_SHA256:raise ValueError('requires pinned DX-Ball PE32')
    output.mkdir(parents=True,exist_ok=False)
    services={name:ServiceDefinition.create(identity='dxball.progression.'+name,types=TYPES,parameters=params,result=RESULTS[name],
        resources=[],effects=['dxball.progression.'+name],outcomes=['return'],
        unobserved=['Shared object identity, callback state and lifetime contract in BOUNDARY.md; concrete comparisons, not checked summaries.']) for name,params in PARAMETERS.items()}
    interface=component_interface(component_id='gameplay-progression',types=TYPES,services=services,
        operations={name:OperationDefinition([('state','progression_state')],'u32' if name=='count' else 'unit',list(PARAMETERS)) for name in RANGES})
    catalog=service_catalog(services).to_payload()
    write_json(output/'interface.json',interface.to_payload());write_json(output/'services.json',catalog);write_json(output/'bridge.json',bridge_spec())
    (output/'bridge.c').write_text(bridge());(output/'progress-runtime.h').write_text(runtime_header())
    sources={'progression.c':HERE/'progression.c','progression-state.h':HERE/'progression-state.h',
        'brick-state.h':HERE.parent/'dxball-brick-actions/brick-state.h'};pending=['paddle-state.h']
    while pending:
        name=pending.pop()
        if name in sources:continue
        path=shared_package/'source'/name
        if not path.is_file():raise ValueError('missing shared header '+name)
        sources[name]=path;pending+=re.findall(r'^#include "([^\"]+)"',path.read_text(),re.MULTILINE)
    args=['component','start','dxball','gameplay-progression','--interface-intent',str(output/'interface.json'),'--service-catalog',str(output/'services.json'),
        '--service-bridge',str(output/'bridge.json'),'--assumption-file',str(HERE/'BOUNDARY.md'),'--remove-source','source/component.c','--output',str(output/'authoring')]
    for name in RANGES:args+=['--operation-symbol',name+'=lifted_progress_'+name]
    for name,path in sources.items():args+=['--source-file','source/'+name+'='+str(path)]
    ran=subprocess.run([sys.executable,'-m','spaghetti_extractor',*args],capture_output=True,text=True)
    (output/'start.stdout').write_text(ran.stdout);(output/'start.stderr').write_text(ran.stderr)
    if ran.returncode:raise RuntimeError('inspect '+str(output/'start.stderr'))
    entries={**{'progress_'+n:r for n,r in RANGES.items()},'startup':(0xeaa0,0xeaa5),**{'progress_service_'+n:(r,r+8) for n,r in HOOKS.items()}}
    (output/'native-image.h').write_text('\n'.join(native_entry_header(original=original,expected_sha256=PE_SHA256,module=None,entry_rva=lo,end_rva=hi,installer='install_'+name) for name,(lo,hi) in entries.items()))
    environment=native_environment()
    prepare_comparison_package(interface_package=output/'authoring/interface.json',source_files={n:output/'authoring/source'/n for n in sources},
        operation_symbols={n:'lifted_progress_'+n for n in RANGES},target_id='dxball',component_id='gameplay-progression',
        adapter_files={'runtime.c':HERE/'runtime.c','bridge.c':output/'bridge.c'},
        include_files={'native-image.h':output/'native-image.h','progress-runtime.h':output/'progress-runtime.h',
            'play-native.h':HERE.parent/'dxball-gameplay/play-native.h','motion-native.h':HERE.parent/'dxball-ball-motion/motion-native.h',
            **native_adapter_headers('pe32-entry-hook.h'),**observation_headers()},
        **{**environment,'runtime_files':{**environment['runtime_files'],'DXBall.exe':original}},original_files=['runtime/DXBall.exe'],oracle_kind='native-original',
        cases=[dict(id=n,arguments=[str(i)]) for i,n in enumerate(CASE_NAMES)],observation_fields=['progression'],
        assumptions=[(HERE/'BOUNDARY.md').read_text()],scope='Eight native gameplay progression entries with shared state, mutable services and ordered round transitions without game startup.',
        service_catalog=catalog,service_bridge=bridge_spec(),export_adapters=['adapters/bridge.c'],
        program_driver=dict(kind='pe32-import',image='runtime/DXBall.exe',library='dx-progress.dll',symbol='dx_progress_anchor'),output=output/'gameplay-progression')
    write_json(output/'preparation.json',dict(seconds=time.monotonic()-start,cases=len(CASE_NAMES),original_source_consulted=False,tool_internal_changes=False))

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('original','shared_package','output'):p.add_argument(name,type=Path)
    a=p.parse_args();prepare(a.original.resolve(),a.shared_package.resolve(),a.output.resolve())
