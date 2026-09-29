"""Lift the board renderer through existing shared board and graphics interfaces."""
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
from spaghetti_extractor.components.service_authoring import OperationDefinition,ServiceDefinition,component_interface,service_catalog
from spaghetti_extractor.util import sha256_file,write_json

HERE=Path(__file__).resolve().parent
MENU=HERE.parent/'dxball-menu';BOARDS=HERE.parent/'dxball-board-data'
def module(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value
menu=module('render_menu_preparation',MENU/'prepare.py')
boards=module('render_board_preparation',BOARDS/'prepare.py')
RANGES=dict(draw=(0x5a90,0x5ac4),cell=(0x5ad0,0x5c1d))
PARAMETERS={name:menu.PARAMETERS[name] for name in ['sprite_destination','sprite','blit_fast','damage']}
TYPES=[*menu.TYPES,dict(id='board_renderer',kind='opaque',nominal_id='dxball.board.renderer')]
C_TYPES={**menu.C_TYPES,'board_renderer':'board_renderer *'}
OPERATIONS=dict(draw=[('state','board_renderer'),('mode','u32')],
    cell=[('state','board_renderer'),('column','u32'),('row','u32'),('mode','u32')])


def bridge_spec():
    return dict(adapters={name:dict(symbol='render_'+name,kind='portable',context=True,outcomes={'return':None})
        for name in PARAMETERS},transports={},native_symbol=None)


def bridge():
    text='#include "portable-component-implementation.h"\n#include "render-runtime.h"\n#include "comparison-service-bridge.h"\n'
    for i,(name,parameters) in enumerate(OPERATIONS.items()):
        signature=', '.join(C_TYPES[t]+' '+n for n,t in parameters);args=', '.join(n for n,_ in parameters)
        text+=f'''void fixture_render_{name}({signature}) {{
    render_enter({i}); spx_board_rendering_services_v5 services=spx_board_rendering_bind_services(NULL);
    spx_board_rendering_context_v5 context={{0}}; context.services=&services;
    spx_board_rendering_services_begin(); lifted_render_{name}(&context,{args}); spx_board_rendering_services_end();
}}
'''
    return text


def runtime_header():
    text='#ifndef DXBALL_RENDER_RUNTIME_H\n#define DXBALL_RENDER_RUNTIME_H\n#include "render-state.h"\n#include "menu-runtime.h"\nvoid render_enter(unsigned);\n'
    for name,parameters in OPERATIONS.items():text+='void fixture_render_'+name+'('+','.join(C_TYPES[t] for _,t in parameters)+');\n'
    for name,parameters in PARAMETERS.items():text+='void render_'+name+'(void *'+''.join(', '+C_TYPES[t] for _,t in parameters)+');\n'
    return text+'#endif\n'


def cases():
    names=['editor','gameplay','deferred-damage','aliased-background','callback-state',
        'callback-rectangle','all-byte-values','real-board']
    return [dict(id=name,arguments=[str(i)]) for i,name in enumerate(names)]


def prepare(original,menu_package,board_package,output):
    started=time.monotonic()
    if sha256_file(original)!=boards.PE_SHA256:raise ValueError('requires pinned DX-Ball PE32')
    output.mkdir(parents=True,exist_ok=False)
    definitions={name:ServiceDefinition.create(identity='dxball.board.render.'+name,types=TYPES,
        parameters=parameters,result='unit',resources=[],effects=['dxball.board.render.'+name],outcomes=['return'],
        unobserved=['Shared board/scene/surface state and synchronous graphics contract in BOUNDARY.md.']) for name,parameters in PARAMETERS.items()}
    interface=component_interface(component_id='board-rendering',types=TYPES,services=definitions,
        operations={name:OperationDefinition(parameters,'unit',list(PARAMETERS) if name=='draw' else ['sprite','blit_fast','damage'])
            for name,parameters in OPERATIONS.items()})
    catalog=service_catalog(definitions).to_payload()
    write_json(output/'interface.json',interface.to_payload());write_json(output/'services.json',catalog);write_json(output/'bridge.json',bridge_spec())
    (output/'bridge.c').write_text(bridge());(output/'render-runtime.h').write_text(runtime_header())
    sources={p.name:p for p in (menu_package/'source').glob('*.h')}
    sources.update({'render.c':HERE/'render.c','render-state.h':HERE/'render-state.h','board-state.h':BOARDS/'board-state.h'})
    args=['component','start','dxball','board-rendering','--interface-intent',str(output/'interface.json'),
        '--service-catalog',str(output/'services.json'),'--service-bridge',str(output/'bridge.json'),
        '--assumption-file',str(HERE/'BOUNDARY.md'),'--remove-source','source/component.c','--output',str(output/'authoring')]
    for name in RANGES:args+=['--operation-symbol',name+'=lifted_render_'+name]
    for name,path in sources.items():args+=['--source-file','source/'+name+'='+str(path)]
    ran=subprocess.run([sys.executable,'-m','spaghetti_extractor',*args],capture_output=True,text=True)
    (output/'start.stdout').write_text(ran.stdout);(output/'start.stderr').write_text(ran.stderr)
    if ran.returncode:raise RuntimeError('inspect '+str(output/'start.stderr'))
    header=(menu_package/'headers/native-image.h').read_text()+'\n'+'\n'.join(
        native_entry_header(original=original,expected_sha256=boards.PE_SHA256,module=None,
            entry_rva=lo,end_rva=hi,installer='install_render_'+name) for name,(lo,hi) in RANGES.items())
    (output/'native-image.h').write_text(header)
    includes={p.relative_to(menu_package/'headers').as_posix():p for p in (menu_package/'headers').rglob('*') if p.is_file()}
    includes.update({'native-image.h':output/'native-image.h','render-runtime.h':output/'render-runtime.h',
        'menu-runtime.c':MENU/'runtime.c','scene-runtime.c':menu.SCENE/'runtime.c',
        'title-runtime.c':HERE.parent/'dxball-title-animation/runtime.c'})
    environment=native_environment()
    prepare_comparison_package(interface_package=output/'authoring/interface.json',
        source_files={name:output/'authoring/source'/name for name in sources},
        operation_symbols={name:'lifted_render_'+name for name in RANGES},target_id='dxball',component_id='board-rendering',
        adapter_files={'runtime.c':HERE/'runtime.c','bridge.c':output/'bridge.c'},include_files=includes,
        **{**environment,'runtime_files':{**environment['runtime_files'],'DXBall.exe':original,'default.bds':board_package/'runtime/default.bds'}},
        original_files=['runtime/DXBall.exe'],oracle_kind='native-original',cases=cases(),observation_fields=['rendering','objects'],
        assumptions=[(HERE/'BOUNDARY.md').read_text()],scope='Actual board/cell entries with live shared board, scene and sprite objects, controlled synchronous graphics services.',
        service_catalog=catalog,service_bridge=bridge_spec(),**bind_dependencies(consumers={'menu-consumer':menu_package}),
        export_adapters=['adapters/bridge.c'],program_driver=dict(kind='pe32-import',image='runtime/DXBall.exe',library='dx-render.dll',symbol='dx_render_anchor'),output=output/'board-rendering')
    write_json(output/'preparation.json',dict(seconds=time.monotonic()-started,cases=len(cases()),original_source_consulted=False,tool_internal_changes=False))


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('original','menu_package','board_package','output'):p.add_argument(name,type=Path)
    a=p.parse_args();prepare(a.original.resolve(),a.menu_package.resolve(),a.board_package.resolve(),a.output.resolve())
