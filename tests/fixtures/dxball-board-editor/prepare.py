"""Author the native board editor through the existing scene and board boundaries."""
import argparse
import importlib.util
from pathlib import Path
import subprocess
import sys
import time

import pefile

from spaghetti_extractor.components.comparison_composition import bind_dependencies
from spaghetti_extractor.components.comparison_environment import native_environment
from spaghetti_extractor.components.comparison_original import native_entry_header
from spaghetti_extractor.components.comparison_package import prepare_comparison_package
from spaghetti_extractor.components.service_authoring import OperationDefinition,ServiceDefinition,component_interface,service_catalog
from spaghetti_extractor.util import sha256_file,write_json

HERE=Path(__file__).resolve().parent
MENU=HERE.parent/'dxball-menu';BOARDS=HERE.parent/'dxball-board-data'
def module(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    result=importlib.util.module_from_spec(spec);spec.loader.exec_module(result);return result
menu=module('editor_menu_preparation',MENU/'prepare.py')
boards=module('editor_board_preparation',BOARDS/'prepare.py')
RANGES=dict(enter=(0x3570,0x3658),redraw=(0x3660,0x3748),update=(0x3750,0x39f7),
    key=(0x3a00,0x3b54),draw_palette=(0x3b60,0x3bc4),draw_status=(0x3bd0,0x3d41),leave=(0x3f30,0x3f6d))
COMMON=[name for name in menu.COMMON if name!='center']
REUSED=['blit_fast','damage']
PARAMETERS={**{name:menu.PARAMETERS[name] for name in [*COMMON,*REUSED]},
    'sprite':[('state','menu_state'),('slot','u32'),('x','u32'),('y','u32')],
    'sprite_id':[('kind','u32')],
    **{name+'_board':[('state','board_set'),('index','u32')] for name in ('select','store')},
    **{name+'_boards':[('state','board_set'),('name','board_name')] for name in ('load','save')},
    'reset_regions':[('state','board_editor'),('count','u32')],
    'define_region':[('state','board_editor'),('index','u32'),('rectangle','font_rect')],
    'hit_region':[('state','board_editor'),('x','u32'),('y','u32')],
    'cursor':[('state','board_editor'),('slot','u32'),('x','u32'),('y','u32')],
    'draw_board':[('state','board_editor'),('mode','u32')],
    'draw_cell':[('state','board_editor'),('column','u32'),('row','u32'),('mode','u32')]}
TYPES=list({t['id']:t for t in [*menu.TYPES,*boards.TYPES,
    dict(id='board_editor',kind='opaque',nominal_id='dxball.board.editor')]}.values())
C_TYPES={**menu.C_TYPES,**boards.C_TYPES,'board_editor':'board_editor *'}
RESULTS={name:'u32' if name in ('sprite_id','hit_region') else 'unit' for name in PARAMETERS}
PALETTE=['sprite_destination','sprite_id','sprite','define_region']
STATUS=['sprite_id','sprite','blit_fast','text']
USED=dict(enter=['reset_damage','clear','image','load_bank','select_bank','select_font','damage_background',
    'damage_destination','reset_regions','select_board','redraw_scene','fade'],
    redraw=['clear','blit','draw_board',*PALETTE,*STATUS],
    update=['wait','restore_damage','select_bank','hit_region','cursor','present','draw_cell','store_board',*STATUS,'damage'],
    key=['store_board','select_board','redraw_scene','load_boards','save_boards'],draw_palette=PALETTE,draw_status=STATUS,
    leave=['fade','clear','release_banks','release_sounds','release_track'])
HOOKS=dict(reset_regions=(0xd520,0xd54e),define_region=(0xd550,0xd58d),hit_region=(0xd590,0xd5db),
    cursor=(0x1080,0x1088),draw_board=(0x5a90,0x5ac4),draw_cell=(0x5ad0,0x5ad8))
TEXT=[(0x416470,25),(0x416450,29),(0x416438,20),(0x41641c,26),(0x416400,26),(0x4163e8,21)]


def bridge_spec():
    return dict(adapters={name:dict(symbol='editor_'+name,kind='portable',context=True,outcomes={'return':None})
        for name in PARAMETERS},transports={},native_symbol=None)


def bridge():
    text='#include "portable-component-implementation.h"\n#include "editor-runtime.h"\n#include "comparison-service-bridge.h"\n'
    for index,name in enumerate(RANGES):
        parameter=',uint32_t value' if name in ('key','leave') else '';argument=',value' if parameter else ''
        text+=f'''void fixture_editor_{name}(board_editor *state{parameter}) {{
    editor_enter({index}); spx_board_editor_services_v5 services=spx_board_editor_bind_services(NULL);
    spx_board_editor_context_v5 context={{0}}; context.services=&services;
    spx_board_editor_services_begin(); lifted_editor_{name}(&context,state{argument}); spx_board_editor_services_end();
}}
'''
    return text


def runtime_header():
    text='#ifndef DXBALL_EDITOR_RUNTIME_H\n#define DXBALL_EDITOR_RUNTIME_H\n#include "editor-state.h"\n#include "menu-runtime.h"\n#include "board-runtime.h"\nvoid editor_enter(unsigned);\n'
    for name in RANGES:text+='void fixture_editor_'+name+'(board_editor *'+(',uint32_t' if name in ('key','leave') else '')+');\n'
    for name,parameters in PARAMETERS.items():
        text+=C_TYPES[RESULTS[name]]+' editor_'+name+'(void *'+''.join(', '+C_TYPES[t] for _,t in parameters)+');\n'
    return text+'#endif\n'


def common_adapters():
    text='/* Transport the editor and board backing across shared synchronous services. */\n'
    for name in [*COMMON,*REUSED]:
        parameters=', '.join(C_TYPES[t]+' '+n for n,t in PARAMETERS[name]);arguments=', '.join(n for n,_ in PARAMETERS[name])
        callee='menu_' if name in [*REUSED,'text'] else 'scene_'
        text+=f'''void editor_{name}(void *unused,{parameters}) {{
    EDITOR_PUSH(); {callee}{name}(unused,{arguments}); EDITOR_PULL();
}}
'''
    return text


def cases():
    names=['paint-first','continuous-paint','last-board','empty-tile','negative-cursor','palette-click',
        'erase','high-byte-keys','read-open-failure','write-open-failure','partial-read','strict-board-edge',
        'noncanonical-flags','callback-input-change','real-board-file','last-palette-row']
    return [dict(id=name,arguments=[str(i)]) for i,name in enumerate(names)]


def prepare(original,menu_package,board_package,output):
    started=time.monotonic()
    if sha256_file(original)!=boards.PE_SHA256:raise ValueError('requires pinned DX-Ball PE32')
    output.mkdir(parents=True,exist_ok=False)
    definitions={}
    for name,parameters in PARAMETERS.items():
        identity=('dxball.scene.' if name in COMMON else 'dxball.menu.' if name in REUSED else 'dxball.editor.')+name
        definitions[name]=ServiceDefinition.create(identity=identity,types=TYPES,parameters=parameters,result=RESULTS[name],
            resources=[],effects=[identity],outcomes=['return'],
            unobserved=['Shared objects and synchronous service contract in BOUNDARY.md.' if name in COMMON else
                'Shared object, clock and pixel lease boundary in BOUNDARY.md.' if name in REUSED else
                'Live board bytes, input flags, hit regions and synchronous rendering boundary in BOUNDARY.md.'])
    interface=component_interface(component_id='board-editor',types=TYPES,services=definitions,
        operations={name:OperationDefinition([('state','board_editor')]+([('value','u32')] if name in ('key','leave') else []),
            'unit',list(dict.fromkeys(USED[name]))) for name in RANGES})
    catalog=service_catalog(definitions).to_payload()
    write_json(output/'interface.json',interface.to_payload());write_json(output/'services.json',catalog);write_json(output/'bridge.json',bridge_spec())
    (output/'bridge.c').write_text(bridge());(output/'editor-runtime.h').write_text(runtime_header());(output/'editor-common.h').write_text(common_adapters())
    image=pefile.PE(str(original))
    data='/* Native help spans, in original order and with original lengths. */\n'
    for i,(address,length) in enumerate(TEXT):
        data+='static const unsigned char editor_help_'+str(i)+'[]={'+','.join(str(b) for b in image.get_data(address-0x400000,length))+'};\n'
    data+='static const struct { const unsigned char *data; uint32_t length; } editor_help[]={'+','.join('{editor_help_'+str(i)+','+str(n)+'}' for i,(_,n) in enumerate(TEXT))+'};\n'
    (output/'editor-data.h').write_text(data)
    sources={p.name:p for p in (menu_package/'source').glob('*.h')}
    sources.update({'editor.c':HERE/'editor.c','editor-state.h':HERE/'editor-state.h','editor-data.h':output/'editor-data.h',
        'board-state.h':board_package/'source/board-state.h'})
    args=['component','start','dxball','board-editor','--interface-intent',str(output/'interface.json'),
        '--service-catalog',str(output/'services.json'),'--service-bridge',str(output/'bridge.json'),
        '--assumption-file',str(HERE/'BOUNDARY.md'),'--remove-source','source/component.c','--output',str(output/'authoring')]
    for name in RANGES:args+=['--operation-symbol',name+'=lifted_editor_'+name]
    for name,path in sources.items():args+=['--source-file','source/'+name+'='+str(path)]
    ran=subprocess.run([sys.executable,'-m','spaghetti_extractor',*args],capture_output=True,text=True)
    (output/'start.stdout').write_text(ran.stdout);(output/'start.stderr').write_text(ran.stderr)
    if ran.returncode:raise RuntimeError('inspect '+str(output/'start.stderr'))
    header=(menu_package/'headers/native-image.h').read_text()+'\n'
    entries={**{'editor_'+name:span for name,span in RANGES.items()},**{'editor_service_'+name:span for name,span in HOOKS.items()},
        **{'board_'+name:span for name,span in boards.RANGES.items()},**{'board_service_'+name:span for name,span in boards.HOOKS.items()}}
    header+='\n'.join(native_entry_header(original=original,expected_sha256=boards.PE_SHA256,module=None,
        entry_rva=lo,end_rva=hi,installer='install_'+name) for name,(lo,hi) in entries.items())
    (output/'native-image.h').write_text(header)
    includes={p.relative_to(menu_package/'headers').as_posix():p for p in (menu_package/'headers').rglob('*') if p.is_file()}
    includes.update({'native-image.h':output/'native-image.h','editor-runtime.h':output/'editor-runtime.h',
        'editor-common.h':output/'editor-common.h','editor-native.h':HERE/'editor-native.h',
        'menu-runtime.c':MENU/'runtime.c','scene-runtime.c':menu.SCENE/'runtime.c','board-runtime.h':board_package/'headers/board-runtime.h'})
    environment=native_environment()
    prepare_comparison_package(interface_package=output/'authoring/interface.json',source_files={name:output/'authoring/source'/name for name in sources},
        operation_symbols={name:'lifted_editor_'+name for name in RANGES},target_id='dxball',component_id='board-editor',
        adapter_files={'runtime.c':HERE/'runtime.c','bridge.c':output/'bridge.c'},include_files=includes,
        **{**environment,'runtime_files':{**environment['runtime_files'],'DXBall.exe':original,'default.bds':board_package/'runtime/default.bds'}},
        original_files=['runtime/DXBall.exe'],oracle_kind='native-original',cases=cases(),observation_fields=['editor','objects'],
        assumptions=[(HERE/'BOUNDARY.md').read_text()],scope='Actual editor scene entries with connected board storage, scene/font objects and explicit input/rendering services.',
        service_catalog=catalog,service_bridge=bridge_spec(),**bind_dependencies(consumers={'menu-consumer':menu_package,'board-consumer':board_package}),
        export_adapters=['adapters/bridge.c'],program_driver=dict(kind='pe32-import',image='runtime/DXBall.exe',library='dx-editor.dll',symbol='dx_editor_anchor'),output=output/'board-editor')
    write_json(output/'preparation.json',dict(seconds=time.monotonic()-started,cases=len(cases()),original_source_consulted=False,tool_internal_changes=False))


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('original','menu_package','board_package','output'):p.add_argument(name,type=Path)
    a=p.parse_args();prepare(a.original.resolve(),a.menu_package.resolve(),a.board_package.resolve(),a.output.resolve())
