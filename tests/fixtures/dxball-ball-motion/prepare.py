"""Author and prepare the connected native ball-motion subsystem."""
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
RANGES=dict(create=(0x4d70,0x4e79),update=(0x4e80,0x5707),rebound=(0x5710,0x5901),contact=(0x5910,0x59f8),remove=(0x5a00,0x5a6f))
HOOKS=dict(allocate=0xdf40,free=0xdf30,random=0xae20,stop_sound=0x3370,pan=0x3550,play_sound=0x3210,
    overlap=0xd5e0,paddle_power=0x85d0,particle=0x7b00,explosion=0x6d30,hit=0x5c80,unstick=0x84b0,lose_life=0x8990)
ARGS={name:[] for name in HOOKS}
ARGS.update(random=['limit'],stop_sound=['sound'],pan=['x'],play_sound=['sound','repeat','volume','pan'],
    particle=['x','y','dx','dy','color','gravity'],explosion=['x','y'],hit=['column','row'])
PARAMETERS={name:[('state','ball_motion_state')]+[(key,'u32') for key in ARGS[name]] for name in HOOKS}
PARAMETERS['free']+=[('ball','play_ball')];PARAMETERS['overlap']+=[('a','font_rect'),('b','font_rect')]
RESULTS={name:'play_ball' if name=='allocate' else 'u32' if name in ('random','pan','overlap','hit') else 'unit' for name in HOOKS}
TYPES=[dict(id='unit',kind='void'),dict(id='u32',kind='integer',width_bits=32,signed=False),
    *[dict(id=name,kind='opaque',nominal_id=nominal) for name,nominal in [('ball_motion_state','dxball.motion.state'),('play_ball','dxball.play.ball'),('font_rect','dxball.font.rect')]]]
C_TYPES=dict(unit='void',u32='uint32_t',ball_motion_state='motion_state *',play_ball='play_ball *',font_rect='font_rect *')
CASE_NAMES=['empty','attached','launch','flight','left-wall','right-wall','ceiling','fallen-ball','paddle-rebound','sticky-paddle',
    'fast-rebound-particles','fire-trail','brick-up','brick-down','brick-left','brick-right','piercing-ball','super-ball',
    'multiple-balls','service-mutation','create-empty','create-tail','remove-null','remove-tail','remove-head','rebound-zones',
    'contact-edges','unstick','generated-motion']

def bridge_spec():
    return dict(adapters={name:dict(symbol='motion_'+name,kind='portable',context=True,outcomes={'return':None}) for name in HOOKS},transports={},native_symbol=None)

def bridge():
    text='#include "portable-component-implementation.h"\n#include "motion-runtime.h"\n#include "comparison-service-bridge.h"\n'
    for i,name in enumerate(RANGES):
        result='uint32_t' if name=='contact' else 'void';params=',uint32_t x,uint32_t y' if name=='contact' else '';args=',x,y' if name=='contact' else ''
        text+=f'{result} fixture_motion_{name}(motion_state *state{params}) {{\n    motion_enter({i}); spx_ball_motion_services_v5 services=spx_ball_motion_bind_services(NULL);\n    spx_ball_motion_context_v5 context={{0}}; context.services=&services; spx_ball_motion_services_begin();\n'
        text+=('    uint32_t result=' if name=='contact' else '    ')+f'lifted_motion_{name}(&context,state{args}); spx_ball_motion_services_end();'+(' return result;' if name=='contact' else '')+'\n}\n'
    return text

def runtime_header():
    text='#ifndef DXBALL_MOTION_RUNTIME_H\n#define DXBALL_MOTION_RUNTIME_H\n#include "motion-state.h"\nvoid motion_enter(unsigned);\n'
    for name in RANGES:
        text+=('uint32_t' if name=='contact' else 'void')+' fixture_motion_'+name+'(motion_state *'+(',uint32_t,uint32_t' if name=='contact' else '')+');\n'
    for name,params in PARAMETERS.items():text+=C_TYPES[RESULTS[name]]+' motion_'+name+'(void *'+''.join(', '+C_TYPES[kind] for _,kind in params)+');\n'
    return text+'enum { '+', '.join('MOTION_'+name.upper()+'='+str(i) for i,name in enumerate(HOOKS))+' };\n#endif\n'

def prepare(original,play_package,board_package,output):
    start=time.monotonic()
    if sha256_file(original)!=PE_SHA256:raise ValueError('requires pinned DX-Ball PE32')
    output.mkdir(parents=True,exist_ok=False)
    definitions={name:ServiceDefinition.create(identity='dxball.motion.'+name,types=TYPES,parameters=PARAMETERS[name],result=RESULTS[name],
        resources=[],effects=['dxball.motion.'+name],outcomes=['return'],unobserved=['Shared ball, board and sprite views with synchronous allocation/service effects in BOUNDARY.md; no checked heap summary.']) for name in HOOKS}
    operations={name:OperationDefinition([('state','ball_motion_state')]+([('x','u32'),('y','u32')] if name=='contact' else []),'u32' if name=='contact' else 'unit',list(HOOKS)) for name in RANGES}
    interface=component_interface(component_id='ball-motion',types=TYPES,services=definitions,operations=operations);catalog=service_catalog(definitions).to_payload()
    write_json(output/'interface.json',interface.to_payload());write_json(output/'services.json',catalog);write_json(output/'bridge.json',bridge_spec())
    (output/'bridge.c').write_text(bridge());(output/'motion-runtime.h').write_text(runtime_header())
    sources={'motion.c':HERE/'motion.c','motion-state.h':HERE/'motion-state.h','play-state.h':HERE.parent/'dxball-gameplay/play-state.h'}
    pending=['board-state.h','menu-state.h']
    while pending:
        name=pending.pop()
        if name in sources:continue
        path=next((p/'source'/name for p in (play_package,board_package) if (p/'source'/name).is_file()),None)
        if path is None:raise ValueError('missing shared header '+name)
        sources[name]=path;pending+=re.findall(r'^#include "([^"]+)"',path.read_text(),re.MULTILINE)
    args=['component','start','dxball','ball-motion','--interface-intent',str(output/'interface.json'),'--service-catalog',str(output/'services.json'),
        '--service-bridge',str(output/'bridge.json'),'--assumption-file',str(HERE/'BOUNDARY.md'),'--remove-source','source/component.c','--output',str(output/'authoring')]
    for name in RANGES:args+=['--operation-symbol',name+'=lifted_motion_'+name]
    for name,path in sources.items():args+=['--source-file','source/'+name+'='+str(path)]
    ran=subprocess.run([sys.executable,'-m','spaghetti_extractor',*args],capture_output=True,text=True)
    (output/'start.stdout').write_text(ran.stdout);(output/'start.stderr').write_text(ran.stderr)
    if ran.returncode:raise RuntimeError('inspect '+str(output/'start.stderr'))
    entries={**{'motion_'+n:v for n,v in RANGES.items()},'startup':(0xeaa0,0xeaa5),**{'motion_service_'+n:(v,v+8) for n,v in HOOKS.items()}}
    (output/'native-image.h').write_text('\n'.join(native_entry_header(original=original,expected_sha256=PE_SHA256,module=None,entry_rva=lo,end_rva=hi,installer='install_'+name) for name,(lo,hi) in entries.items()))
    environment=native_environment()
    prepare_comparison_package(interface_package=output/'authoring/interface.json',source_files={name:output/'authoring/source'/name for name in sources},
        operation_symbols={name:'lifted_motion_'+name for name in RANGES},target_id='dxball',component_id='ball-motion',
        adapter_files={'runtime.c':HERE/'runtime.c','bridge.c':output/'bridge.c'},
        include_files={'native-image.h':output/'native-image.h','motion-runtime.h':output/'motion-runtime.h','motion-native.h':HERE/'motion-native.h',
            'play-native.h':HERE.parent/'dxball-gameplay/play-native.h',**native_adapter_headers('pe32-entry-hook.h'),**observation_headers()},
        **{**environment,'runtime_files':{**environment['runtime_files'],'DXBall.exe':original}},original_files=['runtime/DXBall.exe'],oracle_kind='native-original',
        cases=[dict(id=name,arguments=[str(i)]) for i,name in enumerate(CASE_NAMES)],observation_fields=['motion'],
        assumptions=[(HERE/'BOUNDARY.md').read_text()],scope='Actual five-entry ball-motion subsystem over shared live balls, board bytes and sprite dimensions, with controlled synchronous services; no game UI.',
        service_catalog=catalog,service_bridge=bridge_spec(),export_adapters=['adapters/bridge.c'],
        program_driver=dict(kind='pe32-import',image='runtime/DXBall.exe',library='dx-motion.dll',symbol='dx_motion_anchor'),output=output/'ball-motion')
    write_json(output/'preparation.json',dict(seconds=time.monotonic()-start,cases=len(CASE_NAMES),original_source_consulted=False,tool_internal_changes=False))

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('original','play_package','board_package','output'):p.add_argument(name,type=Path)
    a=p.parse_args();prepare(a.original.resolve(),a.play_package.resolve(),a.board_package.resolve(),a.output.resolve())
