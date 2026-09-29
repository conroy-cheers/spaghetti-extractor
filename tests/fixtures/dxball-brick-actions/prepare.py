"""Prepare the actual brick rules and effect lifecycle with ordinary C adapters."""
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
RANGES=dict(reset=(0x5a70,0x5a8f),hit=(0x5c80,0x5fd7),advance=(0x6020,0x606f),
    blast=(0x6070,0x613a),step_blast=(0x6140,0x640a),queue=(0x6410,0x64a4),
    flash=(0x64b0,0x65d5),step_flash=(0x65e0,0x6730))
OP_ARGS={name:[] for name in RANGES}
OP_ARGS.update(hit=['column','row'],blast=['column','row'],queue=['column','row'],flash=['column','row','tile','transient'])
HOOKS=dict(allocate=0xdf40,free=0xdf30,select_board=0x3ed0,pan=0x3550,stop_sound=0x3370,
    play_sound=0x3210,random=0xae20,particle=0x7b00,debris=0x6ef0,destination=0xbd60,
    cell=0x5ad0,sprite_fast=0x1140,sprite_opaque=0xbdd0,sprite_transparent=0xbd90,erase=0x1280)
ARGS=dict(select_board=['index'],pan=['x'],stop_sound=['sound'],play_sound=['sound','repeat','volume','pan'],
    random=['limit'],particle=['x','y','dx','dy','color','gravity'],debris=['column','row','dx','dy'],
    cell=['column','row','mode'],sprite_fast=['slot','x','y'],sprite_opaque=['slot','x','y'],sprite_transparent=['slot','x','y'])
PARAMETERS={name:[('state','brick_state')]+[(arg,'u32') for arg in args] for name,args in ARGS.items()}
PARAMETERS.update(allocate_effect=[('state','brick_state')],allocate_event=[('state','brick_state')],
    free_effect=[('state','brick_state'),('effect','brick_effect')],destination=[('state','brick_state'),('surface','cleanup_surface')],
    erase=[('state','brick_state'),('rectangle','font_rect')],blit_fast=[('state','brick_state'),('destination','cleanup_surface'),
        ('x','u32'),('y','u32'),('source','cleanup_surface'),('rectangle','font_rect'),('flags','u32')])
PARAMETERS['read_cell']=[('state','brick_state'),('column','u32'),('row','u32')]
for name in ('write_cell','write_pending'):
    PARAMETERS[name]=[('state','brick_state'),('column','u32'),('row','u32'),('value','u32')]
RESULTS={name:'u32' if name in ('pan','random','read_cell') else 'brick_effect' if name=='allocate_effect' else 'play_event' if name=='allocate_event' else 'unit' for name in PARAMETERS}
TYPES=[dict(id='unit',kind='void'),dict(id='u32',kind='integer',width_bits=32,signed=False),
    *[dict(id=name,kind='opaque',nominal_id=nominal) for name,nominal in [('brick_state','dxball.brick.state'),
        ('brick_effect','dxball.brick.effect'),('play_event','dxball.play.event'),('cleanup_surface','dxball.cleanup.surface'),('font_rect','dxball.font.rect')]]]
C_TYPES=dict(unit='void',u32='uint32_t',brick_state='brick_state *',brick_effect='brick_effect *',play_event='play_event *',cleanup_surface='font_surface *',font_rect='font_rect *')
CASE_NAMES=['hit-all-tiles','hit-piercing','hit-invalid-bytes','hit-fast-sparks','pan-mutation','allocation-mutation',
    'sound-mutation','drawing-mutation','reset','queue','blast-center','blast-corner','blast-edge','blast-ordinary',
    'blast-delay','flash-sequence','flash-mutation','remove-middle','free-mutation','unknown-effect','generated-sequences']
QUEUE_CASE_NAMES=['queue-saved-empty','queue-saved-filled','queue-live-saved-alias','queue-wrapped-current',
    'queue-pending-alias','queue-external-mapped','queue-inaccessible','queue-saved-last-byte']

def cases():
    return [dict(id=name,arguments=[str(i)]) for i,name in enumerate(CASE_NAMES)]+[
        dict(id=name,arguments=[str(25+i)]) for i,name in enumerate(QUEUE_CASE_NAMES)]

def declarations():
    services={name:ServiceDefinition.create(identity='dxball.brick.'+name,types=TYPES,parameters=params,result=RESULTS[name],
        resources=[],effects=['dxball.brick.'+name],outcomes=['return'],
        nonlocal_outcomes=['memory-fault'] if name in ('read_cell','write_cell','write_pending') else [],
        unobserved=['Shared storage and ordered service effects in BOUNDARY.md; concrete comparisons, not checked heap summaries.']) for name,params in PARAMETERS.items()}
    interface=component_interface(component_id='brick-actions',types=TYPES,services=services,
        operations={name:OperationDefinition([('state','brick_state')]+[(arg,'u32') for arg in OP_ARGS[name]],'u32' if name=='hit' else 'unit',list(PARAMETERS)) for name in RANGES})
    return interface,service_catalog(services).to_payload()

def bridge_spec():
    return dict(adapters={name:dict(symbol='brick_'+name,kind='portable',context=True,outcomes={'return':None}) for name in PARAMETERS},transports={},native_symbol=None)

def bridge():
    text='#include "portable-component-implementation.h"\n#include "brick-runtime.h"\n#include "comparison-service-bridge.h"\n'
    for i,name in enumerate(RANGES):
        result='uint32_t' if name=='hit' else 'void';params=''.join(',uint32_t '+arg for arg in OP_ARGS[name]);args=''.join(','+arg for arg in OP_ARGS[name])
        text+=f'{result} fixture_brick_{name}(brick_state *state{params}) {{\n    brick_enter({i}); spx_brick_actions_services_v5 services=spx_brick_actions_bind_services(NULL);\n    spx_brick_actions_context_v5 context={{0}}; context.services=&services; spx_brick_actions_services_begin();\n'
        text+=('    uint32_t result=' if name=='hit' else '    ')+f'lifted_brick_{name}(&context,state{args}); spx_brick_actions_services_end();'+(' return result;' if name=='hit' else '')+'\n}\n'
    return text

def runtime_header():
    text='#ifndef DXBALL_BRICK_RUNTIME_H\n#define DXBALL_BRICK_RUNTIME_H\n#include "brick-state.h"\nvoid brick_enter(unsigned);\n'
    for name in RANGES:text+=('uint32_t' if name=='hit' else 'void')+' fixture_brick_'+name+'(brick_state *'+',uint32_t'*len(OP_ARGS[name])+');\n'
    for name,params in PARAMETERS.items():text+=C_TYPES[RESULTS[name]]+' brick_'+name+'(void *'+''.join(', '+C_TYPES[t] for _,t in params)+');\n'
    return text+'enum { '+', '.join('BRICK_'+name.upper()+'='+str(i) for i,name in enumerate(PARAMETERS))+' };\n#endif\n'

def prepare(original,motion_package,output):
    start=time.monotonic()
    if sha256_file(original)!=PE_SHA256:raise ValueError('requires pinned DX-Ball PE32')
    output.mkdir(parents=True,exist_ok=False)
    interface,catalog=declarations()
    write_json(output/'interface.json',interface.to_payload());write_json(output/'services.json',catalog);write_json(output/'bridge.json',bridge_spec())
    (output/'bridge.c').write_text(bridge());(output/'brick-runtime.h').write_text(runtime_header())
    sources={'brick.c':HERE/'brick.c','brick-state.h':HERE/'brick-state.h'};pending=['motion-state.h']
    while pending:
        name=pending.pop()
        if name in sources:continue
        path=motion_package/'source'/name
        if not path.is_file():raise ValueError('missing shared header '+name)
        sources[name]=path;pending+=re.findall(r'^#include "([^"]+)"',path.read_text(),re.MULTILINE)
    args=['component','start','dxball','brick-actions','--interface-intent',str(output/'interface.json'),'--service-catalog',str(output/'services.json'),
        '--service-bridge',str(output/'bridge.json'),'--assumption-file',str(HERE/'BOUNDARY.md'),'--remove-source','source/component.c','--output',str(output/'authoring')]
    for name in RANGES:args+=['--operation-symbol',name+'=lifted_brick_'+name]
    for name,path in sources.items():args+=['--source-file','source/'+name+'='+str(path)]
    ran=subprocess.run([sys.executable,'-m','spaghetti_extractor',*args],capture_output=True,text=True)
    (output/'start.stdout').write_text(ran.stdout);(output/'start.stderr').write_text(ran.stderr)
    if ran.returncode:raise RuntimeError('inspect '+str(output/'start.stderr'))
    entries={**{'brick_'+n:r for n,r in RANGES.items()},'startup':(0xeaa0,0xeaa5),**{'brick_service_'+n:(r,r+8) for n,r in HOOKS.items()}}
    (output/'native-image.h').write_text('\n'.join(native_entry_header(original=original,expected_sha256=PE_SHA256,module=None,entry_rva=lo,end_rva=hi,installer='install_'+n) for n,(lo,hi) in entries.items()))
    environment=native_environment()
    prepare_comparison_package(interface_package=output/'authoring/interface.json',source_files={n:output/'authoring/source'/n for n in sources},
        operation_symbols={n:'lifted_brick_'+n for n in RANGES},target_id='dxball',component_id='brick-actions',
        adapter_files={'runtime.c':HERE/'runtime.c','bridge.c':output/'bridge.c'},
        include_files={'native-image.h':output/'native-image.h','brick-runtime.h':output/'brick-runtime.h',
            'play-native.h':HERE.parent/'dxball-gameplay/play-native.h','motion-native.h':HERE.parent/'dxball-ball-motion/motion-native.h',
            **native_adapter_headers('pe32-entry-hook.h'),**observation_headers()},
        **{**environment,'runtime_files':{**environment['runtime_files'],'DXBall.exe':original}},original_files=['runtime/DXBall.exe'],oracle_kind='native-original',
        cases=cases(),observation_fields=['bricks'],
        assumptions=[(HERE/'BOUNDARY.md').read_text()],scope='Actual brick rules, event queue and eight-operation effect lifecycle over shared board/play state with controlled services, without application startup.',
        service_catalog=catalog,service_bridge=bridge_spec(),export_adapters=['adapters/bridge.c'],
        program_driver=dict(kind='pe32-import',image='runtime/DXBall.exe',library='dx-bricks.dll',symbol='dx_bricks_anchor'),output=output/'brick-actions')
    write_json(output/'preparation.json',dict(seconds=time.monotonic()-start,cases=len(cases()),original_source_consulted=False,tool_internal_changes=False))

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('original','motion_package','output'):p.add_argument(name,type=Path)
    a=p.parse_args();prepare(a.original.resolve(),a.motion_package.resolve(),a.output.resolve())
