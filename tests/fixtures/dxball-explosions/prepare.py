"""Prepare the actual explosion lifecycle through shared gameplay root slots."""
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
RANGES=dict(reset=(0x4100,0x4117),create=(0x6d30,0x6e02),draw=(0x6e10,0x6ee2))
OP_ARGS=dict(reset=[],create=['x','y'],draw=[])
HOOKS=dict(allocate=0xdf40,free=0xdf30,terminate=0xe3d0,sprite=0x1080)
PARAMETERS=dict(allocate=[('state','explosion_state')],free=[('state','explosion_state'),('item','explosion')],
    terminate=[('state','explosion_state'),('status','u32')],
    sprite=[('state','explosion_state'),('slot','u32'),('x','u32'),('y','u32')])
RESULTS={name:'explosion' if name=='allocate' else 'unit' for name in HOOKS}
TYPES=[dict(id='unit',kind='void'),dict(id='u32',kind='integer',width_bits=32,signed=False),
    dict(id='explosion_state',kind='opaque',nominal_id='dxball.explosion.state'),
    dict(id='explosion',kind='opaque',nominal_id='dxball.explosion.record')]
C_TYPES=dict(unit='void',u32='uint32_t',explosion_state='explosion_state *',explosion='explosion *')
CASE_NAMES=['empty-draw','reset-empty','reset-live','create-empty','create-tail','creation-clamps','allocation-callback',
    'termination-call','draw-live','expire-single','expire-head','expire-middle','expire-tail','skipped-successor',
    'sprite-current-callback','sprite-frame-callback','sprite-links-callback','free-current-callback',
    'signed-frames','complete-lifecycle','external-current-reset']

def bridge_spec():
    return dict(adapters={name:dict(symbol='explosion_'+name,kind='portable',context=True,outcomes={'return':None}) for name in PARAMETERS},transports={},native_symbol=None)

def bridge():
    text='#include "portable-component-implementation.h"\n#include "explosion-runtime.h"\n#include "comparison-service-bridge.h"\n'
    for i,name in enumerate(RANGES):
        params=''.join(',uint32_t '+arg for arg in OP_ARGS[name]);args=''.join(','+arg for arg in OP_ARGS[name])
        text+=f'void fixture_explosion_{name}(explosion_state *state{params}) {{\n    explosion_enter({i}); spx_explosion_lifecycle_services_v5 services=spx_explosion_lifecycle_bind_services(NULL);\n    spx_explosion_lifecycle_context_v5 context={{0}}; context.services=&services; spx_explosion_lifecycle_services_begin();\n'
        text+=f'    lifted_explosion_{name}(&context,state{args}); spx_explosion_lifecycle_services_end();\n}}\n'
    return text

def runtime_header():
    text='#ifndef DXBALL_EXPLOSION_RUNTIME_H\n#define DXBALL_EXPLOSION_RUNTIME_H\n#include "explosion-state.h"\nvoid explosion_enter(unsigned);\n'
    for name in RANGES:text+='void fixture_explosion_'+name+'(explosion_state *'+',uint32_t'*len(OP_ARGS[name])+');\n'
    for name,params in PARAMETERS.items():text+=C_TYPES[RESULTS[name]]+' explosion_'+name+'(void *'+''.join(', '+C_TYPES[t] for _,t in params)+');\n'
    return text+'enum { '+', '.join('EXPLOSION_'+name.upper()+'='+str(i) for i,name in enumerate(PARAMETERS))+' };\n#endif\n'

def prepare(original,shared_package,output):
    start=time.monotonic()
    if sha256_file(original)!=PE_SHA256:raise ValueError('requires pinned DX-Ball PE32')
    output.mkdir(parents=True,exist_ok=False)
    services={name:ServiceDefinition.create(identity='dxball.explosion.'+name,types=TYPES,parameters=params,result=RESULTS[name],
        resources=[],effects=['dxball.explosion.'+name],outcomes=['return'],unobserved=['Shared explosion roots, payloads, lifetime and ordered service effects in BOUNDARY.md; concrete comparisons, not checked heap summaries.']) for name,params in PARAMETERS.items()}
    interface=component_interface(component_id='explosion-lifecycle',types=TYPES,services=services,
        operations={name:OperationDefinition([('state','explosion_state')]+[(arg,'u32') for arg in OP_ARGS[name]],'unit',list(PARAMETERS)) for name in RANGES})
    catalog=service_catalog(services).to_payload()
    write_json(output/'interface.json',interface.to_payload());write_json(output/'services.json',catalog);write_json(output/'bridge.json',bridge_spec())
    (output/'bridge.c').write_text(bridge());(output/'explosion-runtime.h').write_text(runtime_header())
    sources={'explosion.c':HERE/'explosion.c','explosion-state.h':HERE/'explosion-state.h'};pending=['play-state.h']
    while pending:
        name=pending.pop()
        if name in sources:continue
        path=shared_package/'source'/name
        if not path.is_file():raise ValueError('missing shared header '+name)
        sources[name]=path;pending+=re.findall(r'^#include "([^"]+)"',path.read_text(),re.MULTILINE)
    args=['component','start','dxball','explosion-lifecycle','--interface-intent',str(output/'interface.json'),'--service-catalog',str(output/'services.json'),
        '--service-bridge',str(output/'bridge.json'),'--assumption-file',str(HERE/'BOUNDARY.md'),'--remove-source','source/component.c','--output',str(output/'authoring')]
    for name in RANGES:args+=['--operation-symbol',name+'=lifted_explosion_'+name]
    for name,path in sources.items():args+=['--source-file','source/'+name+'='+str(path)]
    ran=subprocess.run([sys.executable,'-m','spaghetti_extractor',*args],capture_output=True,text=True)
    (output/'start.stdout').write_text(ran.stdout);(output/'start.stderr').write_text(ran.stderr)
    if ran.returncode:raise RuntimeError('inspect '+str(output/'start.stderr'))
    entries={**{'explosion_'+n:r for n,r in RANGES.items()},'startup':(0xeaa0,0xeaa5),**{'explosion_service_'+n:(r,r+8) for n,r in HOOKS.items()}}
    (output/'native-image.h').write_text('\n'.join(native_entry_header(original=original,expected_sha256=PE_SHA256,module=None,entry_rva=lo,end_rva=hi,installer='install_'+n) for n,(lo,hi) in entries.items()))
    environment=native_environment()
    prepare_comparison_package(interface_package=output/'authoring/interface.json',source_files={n:output/'authoring/source'/n for n in sources},
        operation_symbols={n:'lifted_explosion_'+n for n in RANGES},target_id='dxball',component_id='explosion-lifecycle',
        adapter_files={'runtime.c':HERE/'runtime.c','bridge.c':output/'bridge.c'},
        include_files={'native-image.h':output/'native-image.h','explosion-runtime.h':output/'explosion-runtime.h',
            'play-native.h':HERE.parent/'dxball-gameplay/play-native.h','motion-native.h':HERE.parent/'dxball-ball-motion/motion-native.h',
            'motion-state.h':shared_package/'source/motion-state.h','board-state.h':shared_package/'source/board-state.h',
            **native_adapter_headers('pe32-entry-hook.h'),**observation_headers()},
        **{**environment,'runtime_files':{**environment['runtime_files'],'DXBall.exe':original}},original_files=['runtime/DXBall.exe'],oracle_kind='native-original',
        cases=[dict(id=n,arguments=[str(i)]) for i,n in enumerate(CASE_NAMES)],observation_fields=['explosions'],
        assumptions=[(HERE/'BOUNDARY.md').read_text()],scope='Actual reset/create/draw lifecycle over borrowed gameplay root slots and live explosion records without application startup.',
        service_catalog=catalog,service_bridge=bridge_spec(),export_adapters=['adapters/bridge.c'],
        program_driver=dict(kind='pe32-import',image='runtime/DXBall.exe',library='dx-explosions.dll',symbol='dx_explosions_anchor'),output=output/'explosion-lifecycle')
    write_json(output/'preparation.json',dict(seconds=time.monotonic()-start,cases=len(CASE_NAMES),original_source_consulted=False,tool_internal_changes=False))

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('original','shared_package','output'):p.add_argument(name,type=Path)
    a=p.parse_args();prepare(a.original.resolve(),a.shared_package.resolve(),a.output.resolve())
