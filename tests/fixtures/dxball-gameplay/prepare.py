"""Prepare the actual gameplay frame with explicit lists and controlled services."""
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

HERE = Path(__file__).resolve().parent
PE_SHA256 = '191c113582e1f31016a158d40372fa21ea68d9348bf847bbfbc8e7c7bdfe195f'
RANGES = dict(update=(0x44d0, 0x4ac2))
HOOKS = dict(refresh_score=0x8740, move_paddle=0x6730, move_balls=0x4e80, move_shots=0x69c0,
    move_pickups=0x7420, move_trails=0x7bf0, wait=0x2240, restore_damage=0x1430,
    advance_brick_effects=0x6020, sprite=0x1080, draw_explosions=0x6e10, draw_paddle=0x67b0,
    draw_pickups=0x7a40, draw_trails=0x7db0, prepare_last_brick=0x8c20, stop_sound=0x3370,
    draw_last_brick=0x8ed0, present=0x1650, elapsed=0xdb80, cycle=0x2af0, now=0xdb20,
    hit_tile=0x6070, random=0xae20, spawn_debris=0x6ef0, free_event=0xdf30,
    play_sound=0x3210, split=0x7eb0, power=0x8580, next_board=0x8930, advance_stage=0x8b40, fire=0x6af0)
ARGS = {name: [] for name in HOOKS}
ARGS.update(wait=['count'], sprite=['slot','x','y'], stop_sound=['sound'], elapsed=['previous','delay'],
    cycle=['first','last','amount'], hit_tile=['column','row'], random=['limit'],
    spawn_debris=['column','row','dx','dy'], play_sound=['sound','repeat','volume','pan'])
PARAMETERS = {name: [('state','play_state')]+([(key,'u32') for key in ARGS[name]] if name!='free_event' else [('event','play_event')]) for name in HOOKS}
PARAMETERS['read_pending']=[('state','play_state'),('column','u32'),('row','u32')]
RESULTS = {name: 'u32' if name in ('elapsed','now','random','read_pending') else 'unit' for name in PARAMETERS}
TYPES = [dict(id='unit',kind='void'), dict(id='u32',kind='integer',width_bits=32,signed=False),
    dict(id='play_state',kind='opaque',nominal_id='dxball.play.state'),
    dict(id='play_event',kind='opaque',nominal_id='dxball.play.event')]
C_TYPES = dict(unit='void',u32='uint32_t',play_state='play_state *',play_event='play_event *')


def bridge_spec():
    return dict(adapters={name:dict(symbol='play_'+name,kind='portable',context=True,outcomes={'return':None})
        for name in PARAMETERS},transports={},native_symbol=None)


def bridge():
    return '''#include "portable-component-implementation.h"
#include "play-runtime.h"
#include "comparison-service-bridge.h"
void fixture_play_update(play_state *state) {
    play_enter(); spx_gameplay_frame_services_v5 services=spx_gameplay_frame_bind_services(NULL);
    spx_gameplay_frame_context_v5 context={0}; context.services=&services;
    spx_gameplay_frame_services_begin(); lifted_play_update(&context,state); spx_gameplay_frame_services_end();
}
'''


def runtime_header():
    text = '#ifndef DXBALL_PLAY_RUNTIME_H\n#define DXBALL_PLAY_RUNTIME_H\n#include "play-state.h"\nvoid play_enter(void);\nvoid fixture_play_update(play_state *);\n'
    for name, parameters in PARAMETERS.items():
        text += C_TYPES[RESULTS[name]]+' play_'+name+'(void *'+''.join(', '+C_TYPES[kind] for _,kind in parameters)+');\n'
    text += 'enum { '+', '.join('PLAY_'+name.upper()+'='+str(i) for i,name in enumerate(PARAMETERS))+' };\n'
    return text+'#endif\n'


def cases():
    names = ['paused-wait','paused-cycle','empty-frame','connected-lists','drawing-callback','event-callback',
             'free-callback','powerup-sequence','last-brick','next-board','remaining-effects','mouse-fire',
             'mouse-limit','signed-flags','velocity-rounding','generated-frame']
    return [dict(id=name,arguments=[str(i)]) for i,name in enumerate(names)]


def declarations():
    definitions = {name:ServiceDefinition.create(identity='dxball.play.'+name,types=TYPES,
        parameters=PARAMETERS[name],result=RESULTS[name],resources=[],effects=['dxball.play.'+name],outcomes=['return'],
        nonlocal_outcomes=['memory-fault'] if name=='read_pending' else [],
        unobserved=['Synchronous gameplay helper and shared-list contract in BOUNDARY.md; concrete comparisons, not a checked heap summary.']) for name in PARAMETERS}
    interface = component_interface(component_id='gameplay-frame',types=TYPES,services=definitions,
        operations={'update':OperationDefinition([('state','play_state')],'unit',list(PARAMETERS))})
    catalog = service_catalog(definitions).to_payload()
    return interface,catalog


def prepare(original, menu_package, output):
    start = time.monotonic()
    if sha256_file(original)!=PE_SHA256: raise ValueError('requires pinned DX-Ball PE32')
    output.mkdir(parents=True,exist_ok=False)
    interface,catalog=declarations()
    write_json(output/'interface.json',interface.to_payload());write_json(output/'services.json',catalog)
    write_json(output/'bridge.json',bridge_spec());(output/'bridge.c').write_text(bridge())
    (output/'play-runtime.h').write_text(runtime_header())
    sources={'play.c':HERE/'play.c','play-state.h':HERE/'play-state.h'}; pending=['menu-state.h']
    while pending:
        name=pending.pop()
        if name in sources:continue
        path=menu_package/'source'/name;sources[name]=path
        pending+=re.findall(r'^#include "([^"]+)"',path.read_text(),re.MULTILINE)
    args=['component','start','dxball','gameplay-frame','--interface-intent',str(output/'interface.json'),
        '--service-catalog',str(output/'services.json'),'--service-bridge',str(output/'bridge.json'),
        '--assumption-file',str(HERE/'BOUNDARY.md'),'--remove-source','source/component.c',
        '--operation-symbol','update=lifted_play_update','--output',str(output/'authoring')]
    for name,path in sources.items():args+=['--source-file','source/'+name+'='+str(path)]
    ran=subprocess.run([sys.executable,'-m','spaghetti_extractor',*args],capture_output=True,text=True)
    (output/'start.stdout').write_text(ran.stdout);(output/'start.stderr').write_text(ran.stderr)
    if ran.returncode:raise RuntimeError('inspect '+str(output/'start.stderr'))
    entries={'play_update':RANGES['update'],'startup':(0xeaa0,0xeaa5),
        **{'play_service_'+name:(address,address+8) for name,address in HOOKS.items()}}
    (output/'native-image.h').write_text('\n'.join(native_entry_header(original=original,expected_sha256=PE_SHA256,
        module=None,entry_rva=lo,end_rva=hi,installer='install_'+name) for name,(lo,hi) in entries.items()))
    environment=native_environment()
    prepare_comparison_package(interface_package=output/'authoring/interface.json',
        source_files={name:output/'authoring/source'/name for name in sources},operation_symbols={'update':'lifted_play_update'},
        target_id='dxball',component_id='gameplay-frame',adapter_files={'runtime.c':HERE/'runtime.c','bridge.c':output/'bridge.c'},
        include_files={'native-image.h':output/'native-image.h','play-runtime.h':output/'play-runtime.h','play-native.h':HERE/'play-native.h',
            **native_adapter_headers('pe32-entry-hook.h'),**observation_headers()},
        **{**environment,'runtime_files':{**environment['runtime_files'],'DXBall.exe':original}},
        original_files=['runtime/DXBall.exe'],oracle_kind='native-original',cases=cases(),observation_fields=['frame'],
        assumptions=[(HERE/'BOUNDARY.md').read_text()],scope='Actual gameplay frame over shared ball, shot and event lists, controlled synchronous services and retained numeric tables; no game UI.',
        service_catalog=catalog,service_bridge=bridge_spec(),export_adapters=['adapters/bridge.c'],
        program_driver=dict(kind='pe32-import',image='runtime/DXBall.exe',library='dx-play.dll',symbol='dx_play_anchor'),output=output/'gameplay-frame')
    write_json(output/'preparation.json',dict(seconds=time.monotonic()-start,cases=len(cases()),original_source_consulted=False,tool_internal_changes=False))


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('original','menu_package','output'):p.add_argument(name,type=Path)
    a=p.parse_args();prepare(a.original.resolve(),a.menu_package.resolve(),a.output.resolve())
