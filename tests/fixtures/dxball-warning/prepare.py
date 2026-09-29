"""Prepare the warning with explicit historical inputs and reusable shared objects."""
import argparse
from pathlib import Path
import re
import subprocess
import sys
import time
from spaghetti_extractor.components.comparison_environment import native_adapter_headers,native_environment,observation_headers
from spaghetti_extractor.components.comparison_original import native_entry_header
from spaghetti_extractor.components.comparison_package import prepare_comparison_package
from spaghetti_extractor.components.service_authoring import OperationDefinition,ServiceDefinition,component_interface,service_catalog
from spaghetti_extractor.util import sha256_file,write_json

HERE=Path(__file__).resolve().parent
PE_SHA256='191c113582e1f31016a158d40372fa21ea68d9348bf847bbfbc8e7c7bdfe195f'
RANGES=dict(prepare=(0x8c20,0x8ec7),draw=(0x8ed0,0x8f6c))
HOOKS=dict(random=0xae20,stop_sound=0x3370,play_sound=0x3210,loop_sound=0x32b0,
    queue=0x6410,explosion=0x6d30,particle=0x7b00,select_bank=0xbd70,damage=0x1200)
ARGS=dict(random=['limit'],now=[],stop_sound=['sound'],play_sound=['sound','repeat','volume','pan'],
    loop_sound=['sound','repeat','volume','pan'],queue=['column','row'],explosion=['x','y'],
    particle=['x','y','dx','dy','color','gravity'],select_bank=['bank'])
PARAMETERS={n:[('state','warning_state')]+[(a,'u32') for a in args] for n,args in ARGS.items()}
PARAMETERS.update(blit_fast=[('state','warning_state'),('destination','cleanup_surface'),('x','u32'),('y','u32'),
    ('source','cleanup_surface'),('bounds','font_rect'),('flags','u32')],damage=[('state','warning_state'),('bounds','font_rect')])
RESULTS={n:'u32' if n in ('now','random') else 'unit' for n in PARAMETERS}
TYPES=[dict(id='unit',kind='void'),dict(id='u32',kind='integer',width_bits=32,signed=False),
    *[dict(id=n,kind='opaque',nominal_id=nominal) for n,nominal in [('warning_state','dxball.warning.state'),
        ('cleanup_surface','dxball.cleanup.surface'),('font_rect','dxball.font.rect')]]]
C_TYPES=dict(unit='void',u32='uint32_t',warning_state='warning_state *',cleanup_surface='font_surface *',font_rect='font_rect *')
CASE_NAMES=['initialize','countdown-short','countdown-volume','deadline-equal','deadline-wrap','slow-particles',
    'column-major-last','high-byte-tile','empty-fallback','unbreakable-fallback','saved-board-coordinates',
    'signed-fallback','clip-left-top','clip-right-bottom','odd-negative-dimensions','sound-mutates-board',
    'queue-callback','explosion-fast-callback','particle-callback','bank-callback',
    'draw-inactive','draw-countdown','draw-blit-callback','draw-damage-callback','draw-bank-callback','prepare-draw-sequence']

def bridge_spec():
    return dict(adapters={n:dict(symbol='warning_'+n,kind='portable',context=True,outcomes={'return':None}) for n in PARAMETERS},transports={},native_symbol=None)

def bridge():
    text='#include "portable-component-implementation.h"\n#include "warning-runtime.h"\n#include "comparison-service-bridge.h"\n'
    for i,n in enumerate(RANGES):
        text+=f'void fixture_warning_{n}(warning_state *state) {{\n    warning_enter({i}); spx_last_brick_warning_services_v5 services=spx_last_brick_warning_bind_services(NULL);\n    spx_last_brick_warning_context_v5 context={{0}}; context.services=&services; spx_last_brick_warning_services_begin();\n    lifted_warning_{n}(&context,state); spx_last_brick_warning_services_end();\n}}\n'
    return text

def runtime_header():
    text='#ifndef DXBALL_WARNING_RUNTIME_H\n#define DXBALL_WARNING_RUNTIME_H\n#include "warning-state.h"\nvoid warning_enter(unsigned);\n'
    for n in RANGES:text+='void fixture_warning_'+n+'(warning_state *);\n'
    for n,params in PARAMETERS.items():text+=C_TYPES[RESULTS[n]]+' warning_'+n+'(void *'+''.join(', '+C_TYPES[t] for _,t in params)+');\n'
    return text+'enum { '+', '.join('WARNING_'+n.upper()+'='+str(i) for i,n in enumerate(PARAMETERS))+' };\n#endif\n'

def prepare(original,shared,output):
    start=time.monotonic();output.mkdir(parents=True,exist_ok=False)
    if sha256_file(original)!=PE_SHA256:raise ValueError('requires pinned DX-Ball PE32')
    services={n:ServiceDefinition.create(identity='dxball.warning.'+n,types=TYPES,parameters=params,result=RESULTS[n],
        resources=[],effects=['dxball.warning.'+n],outcomes=['return'],nonlocal_outcomes=['memory-fault'] if n=='queue' else [],
        unobserved=['Explicit historical input and shared-state/service contract in BOUNDARY.md; practical comparisons, not checked heap summaries.']) for n,params in PARAMETERS.items()}
    interface=component_interface(component_id='last-brick-warning',types=TYPES,services=services,
        operations={n:OperationDefinition([('state','warning_state')],'unit',list(PARAMETERS)) for n in RANGES})
    catalog=service_catalog(services).to_payload()
    write_json(output/'interface.json',interface.to_payload());write_json(output/'services.json',catalog);write_json(output/'bridge.json',bridge_spec())
    (output/'bridge.c').write_text(bridge());(output/'warning-runtime.h').write_text(runtime_header())
    sources={'warning.c':HERE/'warning.c','warning-state.h':HERE/'warning-state.h'};pending=['progression-state.h']
    while pending:
        n=pending.pop()
        if n in sources:continue
        p=shared/'source'/n
        if not p.is_file():raise ValueError('missing shared header '+n)
        sources[n]=p;pending+=re.findall(r'^#include "([^"]+)"',p.read_text(),re.MULTILINE)
    args=['component','start','dxball','last-brick-warning','--interface-intent',str(output/'interface.json'),
        '--service-catalog',str(output/'services.json'),'--service-bridge',str(output/'bridge.json'),
        '--assumption-file',str(HERE/'BOUNDARY.md'),'--remove-source','source/component.c','--output',str(output/'authoring')]
    for n in RANGES:args+=['--operation-symbol',n+'=lifted_warning_'+n]
    for n,p in sources.items():args+=['--source-file','source/'+n+'='+str(p)]
    ran=subprocess.run([sys.executable,'-m','spaghetti_extractor',*args],capture_output=True,text=True)
    (output/'start.stdout').write_text(ran.stdout);(output/'start.stderr').write_text(ran.stderr)
    if ran.returncode:raise ValueError('inspect start.stderr')
    entries={**{'warning_'+n:r for n,r in RANGES.items()},'startup':(0xeaa0,0xeaa5),**{'warning_service_'+n:(r,r+8) for n,r in HOOKS.items()}}
    (output/'native-image.h').write_text('\n'.join(native_entry_header(original=original,expected_sha256=PE_SHA256,
        module=None,entry_rva=lo,end_rva=hi,installer='install_'+n) for n,(lo,hi) in entries.items()))
    env=native_environment()
    prepare_comparison_package(interface_package=output/'authoring/interface.json',source_files={n:output/'authoring/source'/n for n in sources},
        operation_symbols={n:'lifted_warning_'+n for n in RANGES},target_id='dxball',component_id='last-brick-warning',
        adapter_files={'runtime.c':HERE/'runtime.c','bridge.c':output/'bridge.c'},
        include_files={'native-image.h':output/'native-image.h','warning-runtime.h':output/'warning-runtime.h',
            **native_adapter_headers('pe32-entry-hook.h'),**observation_headers()},
        **{**env,'runtime_files':{**env['runtime_files'],'DXBall.exe':original}},original_files=['runtime/DXBall.exe'],oracle_kind='native-original',
        cases=[dict(id=n,arguments=[str(i)]) for i,n in enumerate(CASE_NAMES)],observation_fields=['warning'],
        assumptions=[(HERE/'BOUNDARY.md').read_text()],scope='Native warning preparation/drawing with explicit entry history, shared objects, clocks and observed service interactions, without game startup.',
        service_catalog=catalog,service_bridge=bridge_spec(),export_adapters=['adapters/bridge.c'],
        program_driver=dict(kind='pe32-import',image='runtime/DXBall.exe',library='dx-warning.dll',symbol='dx_warning_anchor'),output=output/'last-brick-warning')
    write_json(output/'preparation.json',dict(seconds=time.monotonic()-start,cases=len(CASE_NAMES),original_source_consulted=False,tool_internal_changes=False))

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for n in ('original','shared','output'):p.add_argument(n,type=Path)
    a=p.parse_args();prepare(a.original.resolve(),a.shared.resolve(),a.output.resolve())
