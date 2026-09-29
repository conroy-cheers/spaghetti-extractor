"""Author the actual score-screen bodies using the existing menu and table consumers."""
import argparse
import importlib.util
from pathlib import Path
import subprocess
import sys
import time

import pefile

HERE=Path(__file__).resolve().parent
MENU=HERE.parent/'dxball-menu'
SCORES=HERE.parent/'dxball-scores'
def module(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    result=importlib.util.module_from_spec(spec);spec.loader.exec_module(result);return result
menu=module('screen_menu_preparation',MENU/'prepare.py')
scores=module('screen_scores_preparation',SCORES/'prepare.py')
from spaghetti_extractor.components.comparison_composition import bind_dependencies
from spaghetti_extractor.components.comparison_environment import native_environment
from spaghetti_extractor.components.comparison_original import native_entry_header
from spaghetti_extractor.components.comparison_package import prepare_comparison_package
from spaghetti_extractor.components.service_authoring import OperationDefinition,ServiceDefinition,component_interface,service_catalog
from spaghetti_extractor.util import sha256_file,write_json

RANGES=dict(enter=(0x9410,0x950d),redraw=(0x9510,0x9698),update=(0x96a0,0x98d7),
    key=(0x98e0,0x98f7),draw_table=(0x9900,0x9a25),edit=(0x9f80,0xa0a7))
COMMON=[*menu.COMMON,'line']
REUSED=['load_track','elapsed','now','cycle_dots_palette']
PARAMETERS={**{name:[('state','scene_state'),*menu.scene.SERVICES[name]] for name in COMMON},
    **{name:menu.PARAMETERS[name] for name in REUSED},
    'measure':[('state','font_state'),('length','u32'),('bytes','font_bytes')],
    'load_scores':[('state','scores_state')],
    'insert_score':[('state','scores_state'),('name','scores_name'),('value','u32')],
    'damage':[('state','score_screen'),('rectangle','font_rect')]}
RESULTS={name:'u32' if name in ('elapsed','now','measure','insert_score') else 'unit' for name in PARAMETERS}
TYPES=list({t['id']:t for t in [*menu.TYPES,*scores.TYPES,
    dict(id='score_screen',kind='opaque',nominal_id='dxball.score.screen')]}.values())
C_TYPES={**menu.C_TYPES,**scores.C_TYPES,'font_state':'font_state *','score_screen':'score_screen *'}
TABLE=['line','measure','text']
REDRAW=['clear','blit','sprite_destination','center',*TABLE]
SHOW=['fade','image','redraw_scene']
EDIT=['insert_score',*SHOW,'wait']
USED=dict(enter=['reset_damage','clear','image','load_bank','select_bank','select_font','load_track',
    'damage_background','damage_destination','load_scores','redraw_scene','fade'],redraw=REDRAW,
    update=['wait','restore_damage','sprite_destination','text','measure','elapsed','now','damage','present','cycle_dots_palette',*SHOW],
    key=EDIT,draw_table=TABLE,edit=EDIT)
TEXT=dict(congratulations=(0x4166a0,22),prompt=(0x41668c,16),score=(0x416680,11),cursor=(0x4166b8,1))


def bridge_spec():
    return dict(adapters={name:dict(symbol='screen_'+name,kind='portable',context=True,outcomes={'return':None})
        for name in PARAMETERS},transports={},native_symbol=None)


def bridge():
    text='#include "portable-component-implementation.h"\n#include "screen-runtime.h"\n#include "comparison-service-bridge.h"\n'
    for index,name in enumerate(RANGES):
        parameter=',uint32_t key' if name in ('key','edit') else ''
        argument=',key' if parameter else ''
        text+=f'''void fixture_screen_{name}(score_screen *state{parameter}) {{
    screen_enter({index}); spx_score_scene_services_v5 services=spx_score_scene_bind_services(NULL);
    spx_score_scene_context_v5 context={{0}}; context.services=&services;
    spx_score_scene_services_begin(); lifted_screen_{name}(&context,state{argument}); spx_score_scene_services_end();
}}
'''
    return text


def runtime_header():
    text='#ifndef DXBALL_SCORE_SCREEN_RUNTIME_H\n#define DXBALL_SCORE_SCREEN_RUNTIME_H\n#include "screen-state.h"\n#include "menu-runtime.h"\n#include "scores-runtime.h"\nvoid screen_enter(unsigned);\n'
    for name in RANGES:text+='void fixture_screen_'+name+'(score_screen *'+(',uint32_t' if name in ('key','edit') else '')+');\n'
    for name,parameters in PARAMETERS.items():
        text+=C_TYPES[RESULTS[name]]+' screen_'+name+'(void *'+''.join(', '+C_TYPES[t] for _,t in parameters)+');\n'
    return text+'#endif\n'


def common_adapters():
    text='/* Synchronize the screen at synchronous calls and callback boundaries. */\n'
    for name in [*COMMON,*REUSED]:
        parameters=', '.join(C_TYPES[t]+' '+n for n,t in PARAMETERS[name]);arguments=', '.join(n for n,_ in PARAMETERS[name])
        result=C_TYPES[RESULTS[name]];prefix='uint32_t result=' if result=='uint32_t' else ''
        callee='menu_' if name in [*REUSED,'text','center'] else 'scene_'
        text+=f'''{result} screen_{name}(void *unused,{parameters}) {{
    SCREEN_PUSH(); {prefix}{callee}{name}(unused,{arguments}); SCREEN_PULL();
    {"return result;" if prefix else ""}
}}
'''
    return text


def cases():
    names=['below-minimum','equal-minimum','unsigned-maximum','timer-still','timer-wrap','full-name',
        'empty-backspace','noncanonical-flags','shifted-letters','noncanonical-shift','right-button',
        'negative-mouse','high-bit-key','last-row-highlight','first-row-highlight','rejected-insert',
        'read-open-failure','write-open-failure','write-denied','retained-real-table']
    return [dict(id=name,arguments=[str(i)]) for i,name in enumerate(names)]


def prepare(original,menu_package,table_package,output):
    started=time.monotonic()
    if sha256_file(original)!=scores.PE_SHA256:raise ValueError('requires pinned DX-Ball PE32')
    output.mkdir(parents=True,exist_ok=False)
    definitions={}
    for name,parameters in PARAMETERS.items():
        identity=('dxball.scene.' if name in COMMON else 'dxball.menu.' if name in REUSED else 'dxball.score_screen.')+name
        gaps=['Shared objects and synchronous service contract in BOUNDARY.md.' if name in COMMON else
            'Shared object, clock and pixel lease boundary in BOUNDARY.md.' if name in REUSED else
            'Shared screen/table backing and synchronous callback boundary in BOUNDARY.md.']
        definitions[name]=ServiceDefinition.create(identity=identity,types=TYPES,parameters=parameters,result=RESULTS[name],
            resources=[],effects=[identity],outcomes=['return'],unobserved=gaps)
    interface=component_interface(component_id='score-scene',types=TYPES,services=definitions,
        operations={name:OperationDefinition([('state','score_screen')]+([('key','u32')] if name in ('key','edit') else []),
            'unit',list(dict.fromkeys(USED[name]))) for name in RANGES})
    catalog=service_catalog(definitions).to_payload()
    write_json(output/'interface.json',interface.to_payload());write_json(output/'services.json',catalog)
    write_json(output/'bridge.json',bridge_spec());(output/'bridge.c').write_text(bridge())
    (output/'screen-runtime.h').write_text(runtime_header());(output/'screen-common.h').write_text(common_adapters())
    image=pefile.PE(str(original))
    (output/'screen-data.h').write_text('/* Display spans from pinned executable, including the original lengths. */\n'+
        ''.join('static const unsigned char screen_text_'+name+'[]={'+','.join(str(b) for b in image.get_data(address-0x400000,length))+'};\n'
            for name,(address,length) in TEXT.items()))
    sources={p.name:p for p in (menu_package/'source').glob('*.h')}
    sources.update({'screen.c':HERE/'screen.c','screen-state.h':HERE/'screen-state.h',
        'screen-data.h':output/'screen-data.h','scores-state.h':table_package/'source/scores-state.h'})
    args=['component','start','dxball','score-scene','--interface-intent',str(output/'interface.json'),
        '--service-catalog',str(output/'services.json'),'--service-bridge',str(output/'bridge.json'),
        '--assumption-file',str(HERE/'BOUNDARY.md'),'--remove-source','source/component.c','--output',str(output/'authoring')]
    for name in RANGES:args+=['--operation-symbol',name+'=lifted_screen_'+name]
    for name,path in sources.items():args+=['--source-file','source/'+name+'='+str(path)]
    ran=subprocess.run([sys.executable,'-m','spaghetti_extractor',*args],capture_output=True,text=True)
    (output/'start.stdout').write_text(ran.stdout);(output/'start.stderr').write_text(ran.stderr)
    if ran.returncode:raise RuntimeError('inspect '+str(output/'start.stderr'))
    header=(menu_package/'headers/native-image.h').read_text()+'\n'
    entries={**{'screen_'+name:span for name,span in RANGES.items()},**{'scores_'+name:span for name,span in scores.RANGES.items()},
        **{'scores_service_'+name:span for name,span in scores.HOOKS.items()},'screen_damage':(0x1200,0x1208)}
    header+='\n'.join(native_entry_header(original=original,expected_sha256=scores.PE_SHA256,module=None,
        entry_rva=lo,end_rva=hi,installer='install_'+name) for name,(lo,hi) in entries.items())
    (output/'native-image.h').write_text(header)
    includes={p.relative_to(menu_package/'headers').as_posix():p for p in (menu_package/'headers').rglob('*') if p.is_file()}
    includes.update({'native-image.h':output/'native-image.h','screen-runtime.h':output/'screen-runtime.h',
        'screen-common.h':output/'screen-common.h','screen-native.h':HERE/'screen-native.h',
        'menu-runtime.c':MENU/'runtime.c','scene-runtime.c':menu.SCENE/'runtime.c',
        'scores-runtime.h':table_package/'headers/scores-runtime.h'})
    environment=native_environment()
    prepare_comparison_package(interface_package=output/'authoring/interface.json',source_files={name:output/'authoring/source'/name for name in sources},
        operation_symbols={name:'lifted_screen_'+name for name in RANGES},target_id='dxball',component_id='score-scene',
        adapter_files={'runtime.c':HERE/'runtime.c','bridge.c':output/'bridge.c'},include_files=includes,
        **{**environment,'runtime_files':{**environment['runtime_files'],'DXBall.exe':original,'score.dat':table_package/'runtime/score.dat'}},
        original_files=['runtime/DXBall.exe'],oracle_kind='native-original',cases=cases(),observation_fields=['screen','objects'],
        assumptions=[(HERE/'BOUNDARY.md').read_text()],scope='Actual score-screen bodies, keyboard/timers, shared records and existing connected C scene/font/table services.',
        service_catalog=catalog,service_bridge=bridge_spec(),
        **bind_dependencies(consumers={'menu-consumer':menu_package,'table-consumer':table_package}),
        export_adapters=['adapters/bridge.c'],program_driver=dict(kind='pe32-import',image='runtime/DXBall.exe',library='dx-screen.dll',symbol='dx_screen_anchor'),
        output=output/'score-scene')
    write_json(output/'preparation.json',dict(seconds=time.monotonic()-started,cases=len(cases()),original_source_consulted=False,tool_internal_changes=False))


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('original','menu_package','table_package','output'):p.add_argument(name,type=Path)
    a=p.parse_args();prepare(a.original.resolve(),a.menu_package.resolve(),a.table_package.resolve(),a.output.resolve())
