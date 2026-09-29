"""Prepare the actual pickup creation, motion, collection and disposal with ordinary C adapters."""
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
RANGES=dict(create=(0x6ef0,0x73d3),update=(0x7420,0x79f2),draw=(0x7a40,0x7a8f),remove=(0x7a90,0x7af6))
OP_ARGS={name:[] for name in RANGES};OP_ARGS['create']=['column','row','dx','dy']
HOOKS=dict(allocate=0xdf40,free=0xdf30,random=0xae20,stop_sound=0x3370,pan=0x3550,
    play_sound=0x3210,particle=0x7b00,overlap=0xd5e0,sprite=0x1140,next_board=0x8930,
    unstick=0x84b0,queue_explosive_bricks=0x8260,detonate_bricks=0x8540,release_attached=0x86e0,move_paddle=0x6730,lose_life=0x8990)
ARGS={name:[] for name in HOOKS}
ARGS.update(random=['limit'],stop_sound=['sound'],pan=['x'],play_sound=['sound','repeat','volume','pan'],
    particle=['x','y','dx','dy','color','gravity'],sprite=['slot','x','y'])
PARAMETERS={name:[('state','pickup_state')]+[(arg,'u32') for arg in args] for name,args in ARGS.items()}
PARAMETERS['free']=[('state','pickup_state'),('item','pickup')]
PARAMETERS['overlap']=[('state','pickup_state'),('paddle','font_rect'),('bounds','font_rect')]
RESULTS={name:'u32' if name in ('pan','random','overlap') else 'pickup' if name=='allocate' else 'unit' for name in PARAMETERS}
TYPES=[dict(id='unit',kind='void'),dict(id='u32',kind='integer',width_bits=32,signed=False),
    *[dict(id=name,kind='opaque',nominal_id=nominal) for name,nominal in [('pickup_state','dxball.pickup.state'),
        ('pickup','dxball.pickup.object'),('font_rect','dxball.font.rect')]]]
C_TYPES=dict(unit='void',u32='uint32_t',pickup_state='pickup_state *',pickup='pickup *',font_rect='font_rect *')
CASE_NAMES=['create-all-kinds','create-rare-fallback','create-slow-particles','create-suppressed','allocation-callback',
    'random-callback','creation-audio-callback','movement-boundaries','collect-all-kinds','paddle-resizing',
    'no-overlap','bounce-callback','overlap-callback','collection-audio-callback','release-callback','next-board-callback',
    'draw-list','draw-callback','remove-positions','free-callback','update-list-removal','generated-sequence']

def bridge_spec():
    return dict(adapters={name:dict(symbol='pickup_'+name,kind='portable',context=True,outcomes={'return':None}) for name in PARAMETERS},transports={},native_symbol=None)

def bridge():
    text='#include "portable-component-implementation.h"\n#include "pickup-runtime.h"\n#include "comparison-service-bridge.h"\n'
    for i,name in enumerate(RANGES):
        params=''.join(',uint32_t '+arg for arg in OP_ARGS[name]);args=''.join(','+arg for arg in OP_ARGS[name])
        text+=f'void fixture_pickup_{name}(pickup_state *state{params}) {{\n    pickup_enter({i}); spx_pickup_lifecycle_services_v5 services=spx_pickup_lifecycle_bind_services(NULL);\n    spx_pickup_lifecycle_context_v5 context={{0}}; context.services=&services; spx_pickup_lifecycle_services_begin();\n'
        text+=f'    lifted_pickup_{name}(&context,state{args}); spx_pickup_lifecycle_services_end();\n}}\n'
    return text

def runtime_header():
    text='#ifndef DXBALL_PICKUP_RUNTIME_H\n#define DXBALL_PICKUP_RUNTIME_H\n#include "pickup-state.h"\nvoid pickup_enter(unsigned);\n'
    for name in RANGES:text+='void fixture_pickup_'+name+'(pickup_state *'+',uint32_t'*len(OP_ARGS[name])+');\n'
    for name,params in PARAMETERS.items():text+=C_TYPES[RESULTS[name]]+' pickup_'+name+'(void *'+''.join(', '+C_TYPES[t] for _,t in params)+');\n'
    return text+'enum { '+', '.join('PICKUP_'+name.upper()+'='+str(i) for i,name in enumerate(PARAMETERS))+' };\n#endif\n'

def prepare(original,motion_package,output):
    start=time.monotonic()
    if sha256_file(original)!=PE_SHA256:raise ValueError('requires pinned DX-Ball PE32')
    output.mkdir(parents=True,exist_ok=False)
    services={name:ServiceDefinition.create(identity='dxball.pickup.'+name,types=TYPES,parameters=params,result=RESULTS[name],
        resources=[],effects=['dxball.pickup.'+name],outcomes=['return'],unobserved=['Shared storage and ordered service effects in BOUNDARY.md; concrete comparisons, not checked heap summaries.']) for name,params in PARAMETERS.items()}
    interface=component_interface(component_id='pickup-lifecycle',types=TYPES,services=services,
        operations={name:OperationDefinition([('state','pickup_state')]+[(arg,'u32') for arg in OP_ARGS[name]],'unit',list(PARAMETERS)) for name in RANGES})
    catalog=service_catalog(services).to_payload()
    write_json(output/'interface.json',interface.to_payload());write_json(output/'services.json',catalog);write_json(output/'bridge.json',bridge_spec())
    (output/'bridge.c').write_text(bridge());(output/'pickup-runtime.h').write_text(runtime_header())
    sources={'pickup.c':HERE/'pickup.c','pickup-state.h':HERE/'pickup-state.h'};pending=['motion-state.h']
    while pending:
        name=pending.pop()
        if name in sources:continue
        path=motion_package/'source'/name
        if not path.is_file():raise ValueError('missing shared header '+name)
        sources[name]=path;pending+=re.findall(r'^#include "([^"]+)"',path.read_text(),re.MULTILINE)
    args=['component','start','dxball','pickup-lifecycle','--interface-intent',str(output/'interface.json'),'--service-catalog',str(output/'services.json'),
        '--service-bridge',str(output/'bridge.json'),'--assumption-file',str(HERE/'BOUNDARY.md'),'--remove-source','source/component.c','--output',str(output/'authoring')]
    for name in RANGES:args+=['--operation-symbol',name+'=lifted_pickup_'+name]
    for name,path in sources.items():args+=['--source-file','source/'+name+'='+str(path)]
    ran=subprocess.run([sys.executable,'-m','spaghetti_extractor',*args],capture_output=True,text=True)
    (output/'start.stdout').write_text(ran.stdout);(output/'start.stderr').write_text(ran.stderr)
    if ran.returncode:raise RuntimeError('inspect '+str(output/'start.stderr'))
    entries={**{'pickup_'+n:r for n,r in RANGES.items()},'startup':(0xeaa0,0xeaa5),**{'pickup_service_'+n:(r,r+8) for n,r in HOOKS.items()}}
    (output/'native-image.h').write_text('\n'.join(native_entry_header(original=original,expected_sha256=PE_SHA256,module=None,entry_rva=lo,end_rva=hi,installer='install_'+n) for n,(lo,hi) in entries.items()))
    environment=native_environment()
    prepare_comparison_package(interface_package=output/'authoring/interface.json',source_files={n:output/'authoring/source'/n for n in sources},
        operation_symbols={n:'lifted_pickup_'+n for n in RANGES},target_id='dxball',component_id='pickup-lifecycle',
        adapter_files={'runtime.c':HERE/'runtime.c','bridge.c':output/'bridge.c'},
        include_files={'native-image.h':output/'native-image.h','pickup-runtime.h':output/'pickup-runtime.h',
            'play-native.h':HERE.parent/'dxball-gameplay/play-native.h','motion-native.h':HERE.parent/'dxball-ball-motion/motion-native.h',
            **native_adapter_headers('pe32-entry-hook.h'),**observation_headers()},
        **{**environment,'runtime_files':{**environment['runtime_files'],'DXBall.exe':original}},original_files=['runtime/DXBall.exe'],oracle_kind='native-original',
        cases=[dict(id=n,arguments=[str(i)]) for i,n in enumerate(CASE_NAMES)],observation_fields=['pickups'],
        assumptions=[(HERE/'BOUNDARY.md').read_text()],scope='Actual pickup creation, movement, collection, drawing and disposal over shared gameplay state with controlled services, without application startup.',
        service_catalog=catalog,service_bridge=bridge_spec(),export_adapters=['adapters/bridge.c'],
        program_driver=dict(kind='pe32-import',image='runtime/DXBall.exe',library='dx-pickups.dll',symbol='dx_pickups_anchor'),output=output/'pickup-lifecycle')
    write_json(output/'preparation.json',dict(seconds=time.monotonic()-start,cases=len(CASE_NAMES),original_source_consulted=False,tool_internal_changes=False))

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('original','motion_package','output'):p.add_argument(name,type=Path)
    a=p.parse_args();prepare(a.original.resolve(),a.motion_package.resolve(),a.output.resolve())
