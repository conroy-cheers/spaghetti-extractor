"""Prepare gameplay scene entry, redraw and key handling."""
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
RANGES=dict(enter=(0x4120,0x43cc),redraw=(0x43d0,0x44c5),key=(0x4ad0,0x4ccf))
HOOKS=dict(clear=0x2710,image=0x2490,load_bank=0xc080,select_bank=0xbd70,select_font=0xbd80,
    create_sprite=0xbe10,load_sound=0x3000,load_board=0x5a70,restart=0x8a00,reset_damage=0x1000,
    damage_background=0x1630,damage_destination=0x1640,draw_score=0x8770,draw_board=0x5a90,
    center=0xc720,fade=0x2770,redraw_scene=0xaad0,random=0xae20,stop_music=0x2200,play_music=0x2100)
SERVICES=dict(clear=[('surface','cleanup_surface'),('color','u32')],
    image=[('surface','cleanup_surface'),('name','asset_name'),('palette','u32'),('x','u32'),('y','u32')],
    load_bank=[('bank','u32'),('mode','u32'),('name','asset_name')],select_bank=[('bank','u32')],select_font=[('bank','u32')],
    create_sprite=[('slot','u32'),('left','u32'),('top','u32'),('right','u32'),('bottom','u32')],
    load_sound=[('slot','u32'),('name','asset_name')],load_board=[],restart=[],reset_damage=[],
    damage_background=[('surface','cleanup_surface')],damage_destination=[('surface','cleanup_surface')],
    blit=[('destination','cleanup_surface'),('dr','font_rect'),('source','cleanup_surface'),('sr','font_rect'),('flags','u32')],
    draw_score=[],draw_board=[('mode','u32')],center=[('x','u32'),('y','u32'),('length','u32'),('bytes','font_bytes')],
    fade=[('wait','u32'),('step','u32'),('first','u32'),('last','u32'),('direction','u32')],
    redraw_scene=[],random=[('limit','u32')],stop_music=[],play_music=[('name','asset_name'),('loop','u32')])
PARAMETERS={name:[('state','game_scene_state'),*params] for name,params in SERVICES.items()}
RESULTS={name:'u32' if name=='random' else 'unit' for name in PARAMETERS}
TYPES=[dict(id='unit',kind='void'),dict(id='u32',kind='integer',width_bits=32,signed=False),
    *[dict(id=name,kind='opaque',nominal_id=nominal) for name,nominal in (
        ('game_scene_state','dxball.game.scene.state'),('cleanup_surface','dxball.cleanup.surface'),
        ('asset_name','dxball.asset.name'),('font_rect','dxball.font.rect'),('font_bytes','dxball.font.bytes'))]]
C_TYPES=dict(unit='void',u32='uint32_t',game_scene_state='game_scene_state *',cleanup_surface='font_surface *',
    asset_name='asset_name *',font_rect='font_rect *',font_bytes='font_bytes *')
CASE_NAMES=['enter-flip','enter-primary','enter-aliases','enter-callbacks','redraw-flip','redraw-primary',
    'redraw-no-capability','redraw-negative-capability','redraw-paused','redraw-other-pause-value',
    'redraw-callbacks','redraw-aliases','all-bytes-disabled','all-bytes-enabled','resume-any-key',
    'pause-pending','pause-callbacks','nonboolean-pause','current-sprite-bank','width-wrapping',
    'music-choices','music-callbacks','stereo-direction','enter-redraw-input']

def bridge_spec():
    return dict(adapters={name:dict(symbol='game_'+name,kind='portable',context=True,outcomes={'return':None}) for name in PARAMETERS},transports={},native_symbol=None)

def bridge():
    text='#include "portable-component-implementation.h"\n#include "game-runtime.h"\n#include "comparison-service-bridge.h"\n'
    for i,name in enumerate(RANGES):
        extra=',uint32_t key' if name=='key' else '';argument=',key' if name=='key' else ''
        text+=f'void fixture_game_{name}(game_scene_state *state{extra}) {{\n    game_enter({i}); spx_gameplay_scene_services_v5 services=spx_gameplay_scene_bind_services(NULL);\n    spx_gameplay_scene_context_v5 context={{0}}; context.services=&services; spx_gameplay_scene_services_begin();\n    lifted_game_{name}(&context,state{argument}); spx_gameplay_scene_services_end(); game_exit(state);\n}}\n'
    return text

def runtime_header():
    text='#ifndef DXBALL_GAME_RUNTIME_H\n#define DXBALL_GAME_RUNTIME_H\n#include "game-state.h"\nvoid game_enter(unsigned);\nvoid game_exit(game_scene_state *);\n'
    for name in RANGES:text+='void fixture_game_'+name+'(game_scene_state *'+(',uint32_t' if name=='key' else '')+');\n'
    for name,params in PARAMETERS.items():text+=C_TYPES[RESULTS[name]]+' game_'+name+'(void *'+''.join(', '+C_TYPES[t] for _,t in params)+');\n'
    return text+'enum { '+', '.join('GAME_'+name.upper()+'='+str(i) for i,name in enumerate(PARAMETERS))+' };\n#endif\n'

def prepare(original,shared_package,output):
    start=time.monotonic()
    if sha256_file(original)!=PE_SHA256:raise ValueError('requires pinned DX-Ball PE32')
    output.mkdir(parents=True,exist_ok=False)
    services={name:ServiceDefinition.create(identity='dxball.game.scene.'+name,types=TYPES,parameters=params,result=RESULTS[name],
        resources=[],effects=['dxball.game.scene.'+name],outcomes=['return'],
        unobserved=['Shared object identity, callback state and lifetime contract in BOUNDARY.md; concrete comparisons, not checked summaries.']) for name,params in PARAMETERS.items()}
    interface=component_interface(component_id='gameplay-scene',types=TYPES,services=services,
        operations={name:OperationDefinition([('state','game_scene_state')]+([('key','u32')] if name=='key' else []),'unit',list(PARAMETERS)) for name in RANGES})
    catalog=service_catalog(services).to_payload()
    write_json(output/'interface.json',interface.to_payload());write_json(output/'services.json',catalog);write_json(output/'bridge.json',bridge_spec())
    (output/'bridge.c').write_text(bridge());(output/'game-runtime.h').write_text(runtime_header())
    sources={'game.c':HERE/'game.c','game-state.h':HERE/'game-state.h',
        'damage-state.h':HERE.parent/'dxball-damage/damage-state.h'};pending=['progression-state.h']
    while pending:
        name=pending.pop()
        if name in sources:continue
        path=shared_package/'source'/name
        if not path.is_file():raise ValueError('missing shared header '+name)
        sources[name]=path;pending+=re.findall(r'^#include "([^\"]+)"',path.read_text(),re.MULTILINE)
    args=['component','start','dxball','gameplay-scene','--interface-intent',str(output/'interface.json'),'--service-catalog',str(output/'services.json'),
        '--service-bridge',str(output/'bridge.json'),'--assumption-file',str(HERE/'BOUNDARY.md'),'--remove-source','source/component.c','--output',str(output/'authoring')]
    for name in RANGES:args+=['--operation-symbol',name+'=lifted_game_'+name]
    for name,path in sources.items():args+=['--source-file','source/'+name+'='+str(path)]
    ran=subprocess.run([sys.executable,'-m','spaghetti_extractor',*args],capture_output=True,text=True)
    (output/'start.stdout').write_text(ran.stdout);(output/'start.stderr').write_text(ran.stderr)
    if ran.returncode:raise RuntimeError('inspect '+str(output/'start.stderr'))
    entries={**{'game_'+n:r for n,r in RANGES.items()},'startup':(0xeaa0,0xeaa5),**{'game_service_'+n:(r,r+8) for n,r in HOOKS.items()}}
    (output/'native-image.h').write_text('\n'.join(native_entry_header(original=original,expected_sha256=PE_SHA256,module=None,entry_rva=lo,end_rva=hi,installer='install_'+name) for name,(lo,hi) in entries.items()))
    environment=native_environment()
    prepare_comparison_package(interface_package=output/'authoring/interface.json',source_files={n:output/'authoring/source'/n for n in sources},
        operation_symbols={n:'lifted_game_'+n for n in RANGES},target_id='dxball',component_id='gameplay-scene',
        adapter_files={'runtime.c':HERE/'runtime.c','bridge.c':output/'bridge.c'},
        include_files={'native-image.h':output/'native-image.h','game-runtime.h':output/'game-runtime.h',
            'game-native.h':HERE/'game-native.h','game-services.h':HERE/'game-services.h',
            'play-native.h':HERE.parent/'dxball-gameplay/play-native.h','motion-native.h':HERE.parent/'dxball-ball-motion/motion-native.h',
            **native_adapter_headers('pe32-entry-hook.h'),**observation_headers()},
        **{**environment,'runtime_files':{**environment['runtime_files'],'DXBall.exe':original}},original_files=['runtime/DXBall.exe'],oracle_kind='native-original',
        cases=[dict(id=n,arguments=[str(i)]) for i,n in enumerate(CASE_NAMES)],observation_fields=['game_scene'],
        assumptions=[(HERE/'BOUNDARY.md').read_text()],scope='Gameplay scene entry, redraw and input over existing shared objects without game startup.',
        service_catalog=catalog,service_bridge=bridge_spec(),export_adapters=['adapters/bridge.c'],
        program_driver=dict(kind='pe32-import',image='runtime/DXBall.exe',library='dx-game.dll',symbol='dx_game_anchor'),output=output/'gameplay-scene')
    write_json(output/'preparation.json',dict(seconds=time.monotonic()-start,cases=len(CASE_NAMES),original_source_consulted=False,tool_internal_changes=False))

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('original','shared_package','output'):p.add_argument(name,type=Path)
    a=p.parse_args();prepare(a.original.resolve(),a.shared_package.resolve(),a.output.resolve())
