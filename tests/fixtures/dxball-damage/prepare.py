"""Author damage queues and presentation against native entries, without the UI."""
import argparse
import importlib.util
from pathlib import Path
import subprocess
import sys
import time

from spaghetti_extractor.components.comparison_composition import bind_dependencies
from spaghetti_extractor.components.comparison_environment import native_environment
from spaghetti_extractor.components.comparison_original import native_entry_header
from spaghetti_extractor.components.comparison_package import prepare_comparison_package
from spaghetti_extractor.components.service_authoring import OperationDefinition, ServiceDefinition, component_interface, service_catalog
from spaghetti_extractor.util import sha256_file, write_json

HERE = Path(__file__).resolve().parent
SCENE = HERE.parent/'dxball-title-scene'
spec = importlib.util.spec_from_file_location('damage_scene_preparation', SCENE/'prepare.py')
scene = importlib.util.module_from_spec(spec); spec.loader.exec_module(scene)
PE_SHA256 = scene.title.font.cleanup.PE_SHA256
RANGES = dict(reset=(0x1000,0x107b), transparent=(0x1080,0x1139), opaque=(0x1140,0x11fa),
    mark=(0x1200,0x127f), erase=(0x1280,0x1347), damage=(0x1350,0x1425), restore=(0x1430,0x1621),
    background=(0x1630,0x163a), destination=(0x1640,0x164a), present=(0x1650,0x16fe),
    flush=(0x1700,0x1928), sort=(0x1930,0x1a16), overlap=(0xd5e0,0xd6a8))
HOOKS = dict(now=0xdb20, elapsed=0xdb80, wait=0x2240, recover=0xaaa0)
TYPES = [*scene.TYPES, dict(id='damage_state', kind='opaque', nominal_id='dxball.damage.state')]
C_TYPES = {**scene.C_TYPES, 'damage_state':'damage_state *', 'cleanup_sprite':'font_sprite *'}
STATE = [('state','damage_state')]
RECT = [('rectangle','font_rect')]
SURFACE = [('surface','cleanup_surface')]
OPERATIONS = {name:STATE+parameters for name,parameters in dict(reset=[],
    transparent=[('slot','u32'),('x','u32'),('y','u32')], opaque=[('slot','u32'),('x','u32'),('y','u32')],
    mark=RECT, erase=RECT, damage=RECT, restore=[], background=SURFACE, destination=SURFACE,
    present=[], flush=[], sort=[('first','u32'),('last','u32')], overlap=[('a','font_rect'),('b','font_rect')]).items()}
SERVICES = {name:STATE+parameters for name,parameters in dict(
    sprite_blit=[('destination','cleanup_surface'),('sprite','cleanup_sprite'),('x','u32'),('y','u32'),('flags','u32')],
    blit_fast=[('destination','cleanup_surface'),('x','u32'),('y','u32'),('source','cleanup_surface'),*RECT,('flags','u32')],
    blit=[('destination','cleanup_surface'),('dr','font_rect'),('source','cleanup_surface'),('sr','font_rect'),('flags','u32')],
    now=[], elapsed=[('previous','u32'),('delay','u32')], wait=[('count','u32')], flip=SURFACE, recover=[]).items()}
RESULTS = {name:'u32' if name in ('now','elapsed','flip') else 'unit' for name in SERVICES}
USED = {name:[] for name in OPERATIONS}
USED.update(transparent=['sprite_blit'], opaque=['sprite_blit'], erase=['blit'],
    restore=['blit','blit_fast'], flush=['blit'], present=['now','elapsed','wait','flip','recover','blit'])


def bridge_spec():
    return dict(adapters={name:dict(symbol='damage_'+name,kind='portable',context=True,outcomes={'return':None})
        for name in SERVICES},transports={},native_symbol=None)


def bridge():
    text = '#include "portable-component-implementation.h"\n#include "damage-runtime.h"\n#include "comparison-service-bridge.h"\n'
    for i,(name,parameters) in enumerate(OPERATIONS.items()):
        signature = ', '.join(C_TYPES[t]+' '+n for n,t in parameters)
        args = ', '.join(n for n,_ in parameters)
        result = 'uint32_t' if name=='overlap' else 'void'
        text += f'''{result} fixture_damage_{name}({signature}) {{
    damage_enter({i}); spx_damage_tracking_services_v5 services=spx_damage_tracking_bind_services(NULL);
    spx_damage_tracking_context_v5 context={{0}}; context.services=&services;
    spx_damage_tracking_services_begin();
    {"uint32_t result=" if name=='overlap' else ""}lifted_damage_{name}(&context,{args});
    spx_damage_tracking_services_end(); {"return result;" if name=='overlap' else ""}
}}
'''
    return text


def runtime_header():
    text = '#ifndef DXBALL_DAMAGE_RUNTIME_H\n#define DXBALL_DAMAGE_RUNTIME_H\n#include "damage-state.h"\n#include "damage-observation.h"\n#include "scene-runtime.h"\nvoid damage_enter(unsigned);\n'
    for name,parameters in OPERATIONS.items():
        text += ('uint32_t' if name=='overlap' else 'void')+' fixture_damage_'+name+'('+','.join(C_TYPES[t] for _,t in parameters)+');\n'
    for name,parameters in SERVICES.items():
        text += ('uint32_t' if RESULTS[name]=='u32' else 'void')+' damage_'+name+'(void *'+''.join(', '+C_TYPES[t] for _,t in parameters)+');\n'
    return text+'#endif\n'


def cases():
    names = ['pending-queues','both-pages','single-page','exact-flag-values','clipping','full-capacity',
        'sprite-callback','restore-callback','erase-local-alias','flush-append','flip-retry','flip-recovery',
        'flip-error','clock-wrap','aliased-surfaces','signed-sort','generated-geometry','empty-reset','unbound-reset']
    return [dict(id=name,arguments=[str(i)]) for i,name in enumerate(names)]


def prepare(original, scene_package, output):
    started = time.monotonic()
    if sha256_file(original)!=PE_SHA256: raise ValueError('requires pinned DX-Ball PE32')
    output.mkdir(parents=True,exist_ok=False)
    definitions = {name:ServiceDefinition.create(identity='dxball.damage.'+name,types=TYPES,
        parameters=parameters,result=RESULTS[name],resources=[],effects=['dxball.damage.'+name],outcomes=['return'],
        unobserved=['Synchronous shared queue, sprite, surface and callback contract in BOUNDARY.md.'])
        for name,parameters in SERVICES.items()}
    interface = component_interface(component_id='damage-tracking',types=TYPES,services=definitions,
        operations={name:OperationDefinition(parameters,'u32' if name=='overlap' else 'unit',USED[name])
            for name,parameters in OPERATIONS.items()})
    catalog = service_catalog(definitions).to_payload()
    write_json(output/'interface.json',interface.to_payload()); write_json(output/'services.json',catalog)
    write_json(output/'bridge.json',bridge_spec()); (output/'bridge.c').write_text(bridge())
    (output/'damage-runtime.h').write_text(runtime_header())
    sources = {p.name:p for p in (scene_package/'source').glob('*.h')}
    sources.update({'damage.c':HERE/'damage.c','damage-state.h':HERE/'damage-state.h'})
    args = ['component','start','dxball','damage-tracking','--interface-intent',str(output/'interface.json'),
        '--service-catalog',str(output/'services.json'),'--service-bridge',str(output/'bridge.json'),
        '--assumption-file',str(HERE/'BOUNDARY.md'),'--remove-source','source/component.c','--output',str(output/'authoring')]
    for name in RANGES: args += ['--operation-symbol',name+'=lifted_damage_'+name]
    for name,path in sources.items(): args += ['--source-file','source/'+name+'='+str(path)]
    ran = subprocess.run([sys.executable,'-m','spaghetti_extractor',*args],capture_output=True,text=True)
    (output/'start.stdout').write_text(ran.stdout); (output/'start.stderr').write_text(ran.stderr)
    if ran.returncode: raise RuntimeError('inspect '+str(output/'start.stderr'))
    entries = {**RANGES,**{'service_'+name:(address,address+8) for name,address in HOOKS.items()}}
    header = (scene_package/'headers/native-image.h').read_text()+'\n'+'\n'.join(
        native_entry_header(original=original,expected_sha256=PE_SHA256,module=None,
            entry_rva=lo,end_rva=hi,installer='install_damage_'+name) for name,(lo,hi) in entries.items())
    (output/'native-image.h').write_text(header)
    includes = {p.relative_to(scene_package/'headers').as_posix():p for p in (scene_package/'headers').rglob('*') if p.is_file()}
    includes.update({'native-image.h':output/'native-image.h','damage-runtime.h':output/'damage-runtime.h',
        'damage-native.h':HERE/'damage-native.h','damage-observation.h':HERE/'damage-observation.h','scene-runtime.c':SCENE/'runtime.c',
        'title-runtime.c':scene.TITLE/'runtime.c'})
    environment = native_environment()
    prepare_comparison_package(interface_package=output/'authoring/interface.json',
        source_files={name:output/'authoring/source'/name for name in sources},
        operation_symbols={name:'lifted_damage_'+name for name in RANGES},target_id='dxball',component_id='damage-tracking',
        adapter_files={'runtime.c':HERE/'runtime.c','bridge.c':output/'bridge.c'},include_files=includes,
        **{**environment,'runtime_files':{**environment['runtime_files'],'DXBall.exe':original}},
        original_files=['runtime/DXBall.exe'],oracle_kind='native-original',cases=cases(),observation_fields=['damage','objects'],
        assumptions=[(HERE/'BOUNDARY.md').read_text()],scope='Native queue, cursor and presentation entries with explicit shared state, callback scripts and owned graphics storage; no game UI.',
        service_catalog=catalog,service_bridge=bridge_spec(),**bind_dependencies(consumers={'scene-consumer':scene_package}),
        export_adapters=['adapters/bridge.c'],program_driver=dict(kind='pe32-import',image='runtime/DXBall.exe',library='dx-damage.dll',symbol='dx_damage_anchor'),
        output=output/'damage-tracking')
    write_json(output/'preparation.json',dict(seconds=time.monotonic()-started,cases=len(cases()),original_source_consulted=False,tool_internal_changes=False))


if __name__=='__main__':
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('original','scene_package','output'): p.add_argument(name,type=Path)
    a = p.parse_args(); prepare(a.original.resolve(),a.scene_package.resolve(),a.output.resolve())
