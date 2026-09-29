"""Author sprite drawing through the public component and comparison workflow."""
import argparse
import importlib.util
from pathlib import Path
import subprocess
import sys
import time

HERE = Path(__file__).resolve().parent
FONT = HERE.parent/'dxball-sprite-font'
font_spec=importlib.util.spec_from_file_location('drawing_font_preparation',FONT/'prepare.py')
font_preparation=importlib.util.module_from_spec(font_spec);font_spec.loader.exec_module(font_preparation)
TYPES,RANGES,CLEANUP,cleanup=(getattr(font_preparation,name) for name in ('TYPES','RANGES','CLEANUP','cleanup'))
from spaghetti_extractor.components.comparison_composition import bind_dependencies
from spaghetti_extractor.components.comparison_environment import native_adapter_headers, native_environment, observation_headers
from spaghetti_extractor.components.comparison_original import native_entry_header
from spaghetti_extractor.components.comparison_package import prepare_comparison_package
from spaghetti_extractor.components.service_authoring import OperationDefinition, ServiceDefinition, component_interface, service_catalog
from spaghetti_extractor.util import sha256_file, write_json

DRAW_RANGES = dict(sprite_destination=(0xbd60,0xbd6a), sprite_transparent=(0xbd90,0xbdcf), sprite_opaque=(0xbdd0,0xbe0f))
PARAMETERS = dict(destination=[('state','font_state'),('surface','cleanup_surface')],
    transparent=[('state','font_state'),('slot','u32'),('x','u32'),('y','u32')],
    opaque=[('state','font_state'),('slot','u32'),('x','u32'),('y','u32')])


def bridge_spec():
    return dict(adapters={'blit_fast':dict(symbol='drawing_blit_fast',kind='portable',context=True,
        outcomes={'return':None})},transports={},native_symbol=None)


def bridge():
    text='#include "portable-component-implementation.h"\n#include "drawing-runtime.h"\n#include "comparison-service-bridge.h"\n'
    c_types=dict(font_state='font_state *',cleanup_surface='font_surface *',u32='uint32_t')
    for number,(name,parameters) in enumerate(PARAMETERS.items()):
        result='void' if name=='destination' else 'uint32_t'
        signature=', '.join(c_types[t]+' '+n for n,t in parameters)
        args=', '.join(n for n,_ in parameters)
        text+=f'''{result} fixture_sprite_{name}({signature}) {{
    drawing_enter({number});
    spx_sprite_drawing_services_v5 services=spx_sprite_drawing_bind_services(NULL);
    spx_sprite_drawing_context_v5 context={{0}};context.services=&services;
    spx_sprite_drawing_services_begin();
    {'' if result=='void' else 'uint32_t result = '}lifted_sprite_{name}(&context,{args});
    spx_sprite_drawing_services_end(); {'' if result=='void' else 'return result;'}
}}
'''
    return text


def cases():
    return [dict(id=f'word-{seed}-mode-{mode}',arguments=[str(seed),str(mode)])
            for seed in (0,1,0x7fffffff,0x80000000,0xffffffff) for mode in range(3)]


def prepare(original,font_package,output):
    started=time.monotonic()
    if sha256_file(original)!=cleanup.PE_SHA256:raise ValueError('requires pinned DX-Ball PE32')
    output.mkdir(parents=True,exist_ok=False)
    fast=ServiceDefinition.create(identity='dxball.sprite.blit-fast',types=TYPES,
        parameters=[('state','font_state'),('sprite','cleanup_sprite'),('x','u32'),('y','u32'),('flags','u32')],
        result='u32',resources=[],effects=['dxball.sprite.graphics'],outcomes=['return'],
        unobserved=['Synchronous ordinary C graphics adapter preserving the live source-rectangle alias and observed shared state.'])
    interface=component_interface(component_id='sprite-drawing',types=TYPES,services={'blit_fast':fast},
        operations={name:OperationDefinition(parameters,'unit' if name=='destination' else 'u32',
            [] if name=='destination' else ['blit_fast']) for name,parameters in PARAMETERS.items()})
    catalog=service_catalog({'blit_fast':fast}).to_payload()
    write_json(output/'interface.json',interface.to_payload());write_json(output/'services.json',catalog)
    write_json(output/'bridge.json',bridge_spec());(output/'bridge.c').write_text(bridge())
    args=['component','start','dxball','sprite-drawing','--interface-intent',str(output/'interface.json'),
        '--service-catalog',str(output/'services.json'),'--service-bridge',str(output/'bridge.json'),
        '--assumption-file',str(HERE/'BOUNDARY.md'),'--remove-source','source/component.c','--output',str(output/'authoring')]
    for name in PARAMETERS:args+=['--operation-symbol',name+'=lifted_sprite_'+name]
    sources={'drawing.c':HERE/'drawing.c','font-state.h':FONT/'font-state.h','cleanup-state.h':CLEANUP/'cleanup-state.h'}
    for name,path in sources.items():args+=['--source-file','source/'+name+'='+str(path)]
    ran=subprocess.run([sys.executable,'-m','spaghetti_extractor',*args],capture_output=True,text=True)
    (output/'start.stdout').write_text(ran.stdout);(output/'start.stderr').write_text(ran.stderr)
    if ran.returncode:raise RuntimeError('inspect '+str(output/'start.stderr'))
    (output/'native-image.h').write_text('\n'.join(native_entry_header(original=original,expected_sha256=cleanup.PE_SHA256,
        module=None,entry_rva=lo,end_rva=hi,installer='install_'+name)
        for name,(lo,hi) in {**cleanup.RANGES,**RANGES,**DRAW_RANGES}.items()))
    (output/'case-unit.h').write_text('#define DX_UNIT 2\n#define FONT_UNIT 1\n')
    includes={name:FONT/name for name in ('font-runtime.c','font-runtime.h','font-state.h')}
    includes.update({'drawing-runtime.h':HERE/'drawing-runtime.h','runtime.h':CLEANUP/'runtime.h',
        'cleanup-runtime.c':CLEANUP/'runtime.c','cleanup-state.h':CLEANUP/'cleanup-state.h',
        'native-image.h':output/'native-image.h','case-unit.h':output/'case-unit.h',
        **native_adapter_headers('pe32-entry-hook.h'),**observation_headers()})
    environment=native_environment()
    prepare_comparison_package(interface_package=output/'authoring/interface.json',
        source_files={name:output/'authoring/source'/name for name in sources},
        operation_symbols={name:'lifted_sprite_'+name for name in PARAMETERS},target_id='dxball',component_id='sprite-drawing',
        adapter_files={'runtime.c':HERE/'runtime.c','bridge.c':output/'bridge.c'},include_files=includes,
        **{**environment,'runtime_files':{**environment['runtime_files'],'DXBall.exe':original}},
        original_files=['runtime/DXBall.exe'],oracle_kind='native-original',cases=cases(),
        observation_fields=['before_cleanup','drawing','after_cleanup'],assumptions=[(HERE/'BOUNDARY.md').read_text()],
        scope='Binary-derived sprite drawing with existing font and cleanup consumers, controlled alias-preserving graphics calls.',
        service_catalog=catalog,service_bridge=bridge_spec(),
        **bind_dependencies(consumers={'font-consumer':font_package}),export_adapters=['adapters/bridge.c'],
        program_driver=dict(kind='pe32-import',image='runtime/DXBall.exe',library='dx-drawing.dll',symbol='dx_drawing_anchor'),
        output=output/'sprite-drawing')
    write_json(output/'preparation.json',dict(seconds=time.monotonic()-started,original_source_consulted=False,
        tool_internal_changes=False,operations=list(PARAMETERS),cases=len(cases())))


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('original','font_package','output'):p.add_argument(name,type=Path)
    a=p.parse_args();prepare(a.original.resolve(),a.font_package.resolve(),a.output.resolve())
