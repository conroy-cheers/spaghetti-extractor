"""Prepare typed round-object disposal and gameplay departure."""
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
RANGES=dict(clear=(0x8fd0,0x9221),leave=(0x8f70,0x8fcb))
HOOKS=dict(free=0xdf30,fade=0x2770,clear_surface=0x2710,release_sounds=0x2f90,clear_sprites=0xbcc0,stop_music=0x2200)
PARAMETERS={name:[('state','round_state')] for name in ('release_sounds','clear_sprites','stop_music')}
PARAMETERS.update(free=[('state','round_state'),('storage','round_storage')],
    fade=[('state','round_state'),('wait','u32'),('step','u32'),('first','u32'),('last','u32'),('direction','u32')],
    clear_surface=[('state','round_state'),('surface','cleanup_surface'),('color','u32')])
RESULTS={name:'unit' for name in PARAMETERS}
TYPES=[dict(id='unit',kind='void'),dict(id='u32',kind='integer',width_bits=32,signed=False),
    *[dict(id=name,kind='opaque',nominal_id=nominal) for name,nominal in (
        ('round_state','dxball.round.state'),('round_storage','dxball.round.storage'),('cleanup_surface','dxball.cleanup.surface'))]]
C_TYPES=dict(unit='void',u32='uint32_t',round_state='round_state *',round_storage='round_storage *',cleanup_surface='font_surface *')
CASE_NAMES=['empty','single-each-list','middle-cursors','tail-cursors','null-cursors-with-live-roots',
    'mixed-cursors','balls-only','shots-only','events-and-queue','particles-only','explosions-only',
    'brick-effects-only','pickups-only','staging-only','cancel-later-list','stop-current-list',
    'redirect-current-list','append-to-later-list','repopulate-earlier-list','callback-counters',
    'callback-live-payload','repeat-cleanup','generated-lists','partial-leave','full-leave',
    'pending-full-leave','leave-callbacks','leave-empty']

def bridge_spec():
    return dict(adapters={name:dict(symbol='round_'+name,kind='portable',context=True,outcomes={'return':None}) for name in PARAMETERS},transports={},native_symbol=None)

def bridge():
    text='#include "portable-component-implementation.h"\n#include "round-runtime.h"\n#include "comparison-service-bridge.h"\n'
    for i,name in enumerate(RANGES):
        extra=',uint32_t full' if name=='leave' else '';argument=',full' if name=='leave' else ''
        text+=f'void fixture_round_{name}(round_state *state{extra}) {{\n    round_enter({i}); spx_round_cleanup_services_v5 services=spx_round_cleanup_bind_services(NULL);\n    spx_round_cleanup_context_v5 context={{0}}; context.services=&services; spx_round_cleanup_services_begin();\n    lifted_round_{name}(&context,state{argument}); spx_round_cleanup_services_end(); round_exit(state);\n}}\n'
    return text

def runtime_header():
    text='#ifndef DXBALL_ROUND_RUNTIME_H\n#define DXBALL_ROUND_RUNTIME_H\n#include "round-state.h"\nvoid round_enter(unsigned);\nvoid round_exit(round_state *);\n'
    for name in RANGES:text+='void fixture_round_'+name+'(round_state *'+(',uint32_t' if name=='leave' else '')+');\n'
    for name,params in PARAMETERS.items():text+='void round_'+name+'(void *'+''.join(', '+C_TYPES[t] for _,t in params)+');\n'
    return text+'enum { '+', '.join('ROUND_'+name.upper()+'='+str(i) for i,name in enumerate(PARAMETERS))+' };\n#endif\n'

def prepare(original,shared_package,output):
    start=time.monotonic()
    if sha256_file(original)!=PE_SHA256:raise ValueError('requires pinned DX-Ball PE32')
    output.mkdir(parents=True,exist_ok=False)
    services={name:ServiceDefinition.create(identity='dxball.round.'+name,types=TYPES,parameters=params,result=RESULTS[name],
        resources=[],effects=['dxball.round.'+name],outcomes=['return'],
        unobserved=['Shared object identity, callback state and lifetime contract in BOUNDARY.md; concrete comparisons, not checked summaries.']) for name,params in PARAMETERS.items()}
    interface=component_interface(component_id='round-cleanup',types=TYPES,services=services,
        operations={name:OperationDefinition([('state','round_state')]+([('full','u32')] if name=='leave' else []),'unit',list(PARAMETERS)) for name in RANGES})
    catalog=service_catalog(services).to_payload()
    write_json(output/'interface.json',interface.to_payload());write_json(output/'services.json',catalog);write_json(output/'bridge.json',bridge_spec())
    (output/'bridge.c').write_text(bridge());(output/'round-runtime.h').write_text(runtime_header())
    sources={'round.c':HERE/'round.c','round-state.h':HERE/'round-state.h',
        'power-state.h':HERE.parent/'dxball-powerups/power-state.h',
        'particle-state.h':HERE.parent/'dxball-particles/particle-state.h',
        'explosion-state.h':HERE.parent/'dxball-explosions/explosion-state.h'};pending=['progression-state.h']
    while pending:
        name=pending.pop()
        if name in sources:continue
        path=shared_package/'source'/name
        if not path.is_file():raise ValueError('missing shared header '+name)
        sources[name]=path;pending+=re.findall(r'^#include "([^\"]+)"',path.read_text(),re.MULTILINE)
    args=['component','start','dxball','round-cleanup','--interface-intent',str(output/'interface.json'),'--service-catalog',str(output/'services.json'),
        '--service-bridge',str(output/'bridge.json'),'--assumption-file',str(HERE/'BOUNDARY.md'),'--remove-source','source/component.c','--output',str(output/'authoring')]
    for name in RANGES:args+=['--operation-symbol',name+'=lifted_round_'+name]
    for name,path in sources.items():args+=['--source-file','source/'+name+'='+str(path)]
    ran=subprocess.run([sys.executable,'-m','spaghetti_extractor',*args],capture_output=True,text=True)
    (output/'start.stdout').write_text(ran.stdout);(output/'start.stderr').write_text(ran.stderr)
    if ran.returncode:raise RuntimeError('inspect '+str(output/'start.stderr'))
    entries={**{'round_'+n:r for n,r in RANGES.items()},'startup':(0xeaa0,0xeaa5),**{'round_service_'+n:(r,r+8) for n,r in HOOKS.items()}}
    (output/'native-image.h').write_text('\n'.join(native_entry_header(original=original,expected_sha256=PE_SHA256,module=None,entry_rva=lo,end_rva=hi,installer='install_'+name) for name,(lo,hi) in entries.items()))
    environment=native_environment()
    prepare_comparison_package(interface_package=output/'authoring/interface.json',source_files={n:output/'authoring/source'/n for n in sources},
        operation_symbols={n:'lifted_round_'+n for n in RANGES},target_id='dxball',component_id='round-cleanup',
        adapter_files={'runtime.c':HERE/'runtime.c','bridge.c':output/'bridge.c'},
        include_files={'native-image.h':output/'native-image.h','round-runtime.h':output/'round-runtime.h',
            'play-native.h':HERE.parent/'dxball-gameplay/play-native.h','motion-native.h':HERE.parent/'dxball-ball-motion/motion-native.h',
            **native_adapter_headers('pe32-entry-hook.h'),**observation_headers()},
        **{**environment,'runtime_files':{**environment['runtime_files'],'DXBall.exe':original}},original_files=['runtime/DXBall.exe'],oracle_kind='native-original',
        cases=[dict(id=n,arguments=[str(i)]) for i,n in enumerate(CASE_NAMES)],observation_fields=['round_cleanup'],
        assumptions=[(HERE/'BOUNDARY.md').read_text()],scope='Round cleanup and scene departure dispose nine lists over existing shared object types without game startup.',
        service_catalog=catalog,service_bridge=bridge_spec(),export_adapters=['adapters/bridge.c'],
        program_driver=dict(kind='pe32-import',image='runtime/DXBall.exe',library='dx-round.dll',symbol='dx_round_anchor'),output=output/'round-cleanup')
    write_json(output/'preparation.json',dict(seconds=time.monotonic()-start,cases=len(CASE_NAMES),original_source_consulted=False,tool_internal_changes=False))

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('original','shared_package','output'):p.add_argument(name,type=Path)
    a=p.parse_args();prepare(a.original.resolve(),a.shared_package.resolve(),a.output.resolve())
