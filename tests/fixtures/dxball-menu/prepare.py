"""Prepare the main menu and its dot animation using the existing scene network."""
import argparse
import importlib.util
from pathlib import Path
import subprocess
import sys
import time

import capstone
import pefile

HERE = Path(__file__).resolve().parent
SCENE = HERE.parent/'dxball-title-scene'
spec = importlib.util.spec_from_file_location('menu_scene_preparation',SCENE/'prepare.py')
scene = importlib.util.module_from_spec(spec); spec.loader.exec_module(scene)
from spaghetti_extractor.components.comparison_composition import bind_dependencies
from spaghetti_extractor.components.comparison_environment import native_environment
from spaghetti_extractor.components.comparison_original import native_entry_header
from spaghetti_extractor.components.comparison_package import prepare_comparison_package
from spaghetti_extractor.components.service_authoring import OperationDefinition, ServiceDefinition, component_interface, service_catalog
from spaghetti_extractor.util import sha256_file, write_json

RANGES = dict(enter=(0xae80,0xaf76),redraw=(0xaf80,0xb1e4),update=(0xb1f0,0xb29c),key=(0xb2a0,0xb2ca),
    leave=(0xbbf0,0xbc90),initialize_dots=(0xb2d0,0xba38),animate=(0xba40,0xbbf0))
COMMON = ['reset_damage','clear','image','load_bank','select_bank','select_font','damage_background',
    'damage_destination','redraw_scene','restore_damage','present','fade','sprite_destination','wait',
    'blit','text','center','release_banks','release_sounds','release_track']
EXTRA = dict(load_track=[('state','menu_state'),('name','asset_name'),('mode','u32')],
    elapsed=[('state','menu_state'),('previous','u32'),('delay','u32')],now=[('state','menu_state')],
    blit_fast=[('state','menu_state'),('destination','cleanup_surface'),('x','u32'),('y','u32'),
        ('source','cleanup_surface'),('rectangle','font_rect'),('flags','u32')],
    describe=[('surface','cleanup_surface'),('view','pcx_view')],lock=[('surface','cleanup_surface'),('view','pcx_view')],
    unlock=[('surface','cleanup_surface')],sprite=[('state','menu_state'),('slot','u32'),('x','u32'),('y','u32')],
    damage=[('state','menu_state'),('rectangle','font_rect')],
    cycle_palette=[('state','menu_state'),('first','u32'),('last','u32'),('step','u32')],
    cycle_dots_palette=[('state','menu_state'),('first','u32'),('last','u32'),('step','u32')])
PARAMETERS = {**{name:[('state','scene_state'),*scene.SERVICES[name]] for name in COMMON},**EXTRA}
RESULTS = {name:'u32' if name in ('elapsed','now','lock') else 'unit' for name in PARAMETERS}
TYPES = [*scene.TYPES,dict(id='menu_state',kind='opaque',nominal_id='dxball.menu.state'),
    dict(id='pcx_view',kind='opaque',nominal_id='dxball.pcx.view')]
C_TYPES = {**scene.C_TYPES,'menu_state':'menu_state *','pcx_view':'pcx_view *'}
ANIMATION = ['elapsed','sprite_destination','blit_fast','describe','lock','unlock','sprite','damage','cycle_dots_palette','now']
REDRAW = ['clear','blit','sprite_destination','select_font','wait','text','center']
USED = dict(enter=list(dict.fromkeys([*REDRAW,*ANIMATION,'reset_damage','image','load_bank','select_bank',
    'load_track','damage_background','damage_destination','redraw_scene','restore_damage','present','fade'])),
    redraw=REDRAW,update=[*ANIMATION,'wait','restore_damage','present','cycle_palette'],key=[],
    leave=['fade','clear','blit','release_banks','release_sounds','release_track'],initialize_dots=[],animate=ANIMATION)
HOOKS = dict(load_track=0x2100,elapsed=0xdb80,now=0xdb20,damage=0x1350,cycle_palette=0x2a50,cycle_dots_palette=0x2af0)
TEXT = dict(version=(0x4179e0,6),author=(0x4179cc,19),copyright=(0x41798c,62),
    distribution=(0x41791c,109),based_on=(0x417904,22),by=(0x4178f0,19))


def symbol(name):
    return 'menu_'+name


def bridge_spec():
    return dict(adapters={name:dict(symbol=symbol(name),kind='portable',context=True,outcomes={'return':None})
        for name in PARAMETERS},transports={},native_symbol=None)


def bridge():
    text = '#include "portable-component-implementation.h"\n#include "menu-runtime.h"\n#include "comparison-service-bridge.h"\n'
    for number,name in enumerate(RANGES):
        parameter = ', uint32_t value' if name in ('key','leave') else ''
        argument = ', value' if parameter else ''
        text += f'''void fixture_menu_{name}(menu_state *state{parameter}) {{
    menu_enter({number});
    spx_menu_scene_services_v5 services = spx_menu_scene_bind_services(NULL);
    spx_menu_scene_context_v5 context = {{0}}; context.services = &services;
    spx_menu_scene_services_begin(); lifted_menu_{name}(&context,state{argument}); spx_menu_scene_services_end();
}}
'''
    return text


def runtime_header():
    text = '#ifndef DXBALL_MENU_RUNTIME_H\n#define DXBALL_MENU_RUNTIME_H\n#include "menu-state.h"\n#include "scene-runtime.h"\nvoid menu_enter(unsigned);\n'
    for name in RANGES:
        text += 'void fixture_menu_'+name+'(menu_state *'+(', uint32_t' if name in ('key','leave') else '')+');\n'
    for name in PARAMETERS:
        result = 'uint32_t' if RESULTS[name]=='u32' else 'void'
        text += result+' '+symbol(name)+'(void *'+''.join(', '+C_TYPES[t] for _,t in PARAMETERS[name])+');\n'
    return text+'#endif\n'


def common_adapters():
    text='/* Shared scene services; the live consumer transports menu state around reentrant calls. */\n'
    for name in COMMON:
        if name in ('text','center'): continue
        parameters=', '.join(C_TYPES[t]+' '+n for n,t in PARAMETERS[name])
        arguments=', '.join(n for n,_ in PARAMETERS[name])
        text+=f'''void menu_{name}(void *unused, {parameters}) {{
    MENU_COMMON_PUSH(); scene_{name}(unused, {arguments}); MENU_COMMON_PULL();
}}
'''
    return text


def data_header(original):
    binary=pefile.PE(str(original)); decoder=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_32); decoder.detail=True
    pattern={}
    for instruction in decoder.disasm(binary.get_data(0xb2de,0xb967-0xb2de),0x40b2de):
        operands=instruction.operands
        if instruction.mnemonic!='mov' or len(operands)!=2: raise ValueError('unexpected dot pattern instruction')
        left,right=operands
        if (left.type!=capstone.x86.X86_OP_MEM or left.size!=1 or left.mem.base!=capstone.x86.X86_REG_ESP
                or left.mem.index or right.type!=capstone.x86.X86_OP_REG or right.reg not in (capstone.x86.X86_REG_AL,capstone.x86.X86_REG_BL)):
            raise ValueError('unexpected dot pattern store')
        index=left.mem.disp-0x10
        if index in pattern: raise ValueError('repeated dot pattern store')
        pattern[index]=int(right.reg==capstone.x86.X86_REG_AL)
    if set(pattern)!=set(range(287)): raise ValueError('incomplete dot pattern')
    text='/* Literal display data recovered from the pinned executable. */\n'
    for name,(address,length) in TEXT.items():
        text+='static const unsigned char menu_text_'+name+'[] = {'+','.join(str(b) for b in binary.get_data(address-0x400000,length))+'};\n'
    text+='static const unsigned char menu_pattern[287] = {\n'
    for start in range(0,287,41): text+='    '+','.join(str(pattern[i]) for i in range(start,start+41))+',\n'
    return text+'};\n'


def cases():
    return [dict(id='menu-mode-'+str(mode),arguments=[str(17+mode),str(mode)]) for mode in range(12)]


def prepare(original,scene_package,output):
    started=time.monotonic()
    if sha256_file(original)!=scene.title.font.cleanup.PE_SHA256: raise ValueError('requires pinned DX-Ball PE32')
    output.mkdir(parents=True,exist_ok=False)
    definitions={name:ServiceDefinition.create(identity=('dxball.scene.' if name in COMMON else 'dxball.menu.')+name,
        types=scene.TYPES if name in COMMON else TYPES,parameters=parameters,result=RESULTS[name],resources=[],
        effects=[('dxball.scene.' if name in COMMON else 'dxball.menu.')+name],outcomes=['return'],
        unobserved=['Shared objects and synchronous service contract in BOUNDARY.md.' if name in COMMON else
            'Shared object, clock and pixel lease boundary in BOUNDARY.md.']) for name,parameters in PARAMETERS.items()}
    interface=component_interface(component_id='menu-scene',types=TYPES,services=definitions,
        operations={name:OperationDefinition([('state','menu_state')]+([('value','u32')] if name in ('key','leave') else []),
            'unit',USED[name]) for name in RANGES})
    catalog=service_catalog(definitions).to_payload()
    write_json(output/'interface.json',interface.to_payload()); write_json(output/'services.json',catalog)
    write_json(output/'bridge.json',bridge_spec()); (output/'bridge.c').write_text(bridge())
    (output/'menu-runtime.h').write_text(runtime_header()); (output/'menu-data.h').write_text(data_header(original))
    (output/'menu-common.h').write_text(common_adapters())
    sources={p.name:p for p in (scene_package/'source').iterdir() if p.is_file() and p.suffix=='.h' and p.name!='scene-text.h'}
    sources.update({'menu.c':HERE/'menu.c','menu-state.h':HERE/'menu-state.h','menu-data.h':output/'menu-data.h'})
    args=['component','start','dxball','menu-scene','--interface-intent',str(output/'interface.json'),
        '--service-catalog',str(output/'services.json'),'--service-bridge',str(output/'bridge.json'),
        '--assumption-file',str(HERE/'BOUNDARY.md'),'--remove-source','source/component.c','--output',str(output/'authoring')]
    for name in RANGES: args+=['--operation-symbol',name+'=lifted_menu_'+name]
    for name,path in sources.items(): args+=['--source-file','source/'+name+'='+str(path)]
    ran=subprocess.run([sys.executable,'-m','spaghetti_extractor',*args],capture_output=True,text=True)
    (output/'start.stdout').write_text(ran.stdout); (output/'start.stderr').write_text(ran.stderr)
    if ran.returncode: raise RuntimeError('inspect '+str(output/'start.stderr'))
    header=(scene_package/'headers/native-image.h').read_text()+'\n'
    entries={**{'menu_'+name:span for name,span in RANGES.items()},**{'menu_service_'+name:(rva,rva+8) for name,rva in HOOKS.items()}}
    header+='\n'.join(native_entry_header(original=original,expected_sha256=scene.title.font.cleanup.PE_SHA256,
        module=None,entry_rva=lo,end_rva=hi,installer='install_'+name) for name,(lo,hi) in entries.items())
    (output/'native-image.h').write_text(header)
    includes={p.relative_to(scene_package/'headers').as_posix():p for p in (scene_package/'headers').rglob('*') if p.is_file()}
    includes.update({'native-image.h':output/'native-image.h','menu-runtime.h':output/'menu-runtime.h',
        'menu-native.h':HERE/'menu-native.h','scene-runtime.c':SCENE/'runtime.c',
        'menu-common.h':output/'menu-common.h','title-runtime.c':scene.TITLE/'runtime.c'})
    environment=native_environment()
    prepare_comparison_package(interface_package=output/'authoring/interface.json',
        source_files={name:output/'authoring/source'/name for name in sources},operation_symbols={name:'lifted_menu_'+name for name in RANGES},
        target_id='dxball',component_id='menu-scene',adapter_files={'runtime.c':HERE/'runtime.c','bridge.c':output/'bridge.c'},
        include_files=includes,**{**environment,'runtime_files':{**environment['runtime_files'],'DXBall.exe':original}},
        original_files=['runtime/DXBall.exe'],oracle_kind='native-original',cases=cases(),observation_fields=['menu','objects'],
        assumptions=[(HERE/'BOUNDARY.md').read_text()],scope='Main menu and shared dot animation with existing scene/font/graphics components and live pixel storage.',
        service_catalog=catalog,service_bridge=bridge_spec(),**bind_dependencies(consumers={'scene-consumer':scene_package}),
        export_adapters=['adapters/bridge.c'],program_driver=dict(kind='pe32-import',image='runtime/DXBall.exe',
            library='dx-menu.dll',symbol='dx_menu_anchor'),output=output/'menu-scene')
    write_json(output/'preparation.json',dict(seconds=time.monotonic()-started,cases=len(cases()),original_source_consulted=False,tool_internal_changes=False))


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('original','scene_package','output'): parser.add_argument(name,type=Path)
    args=parser.parse_args(); prepare(args.original.resolve(),args.scene_package.resolve(),args.output.resolve())
