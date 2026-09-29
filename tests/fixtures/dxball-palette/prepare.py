"""Prepare the remaining shared palette bodies from a retained DX-Ball environment."""
import argparse
from pathlib import Path
import subprocess
import sys
import time
from spaghetti_extractor.components.comparison_environment import native_environment,native_adapter_headers,observation_headers
from spaghetti_extractor.components.comparison_package import prepare_comparison_package
from spaghetti_extractor.components.service_authoring import OperationDefinition,ServiceDefinition,component_interface,service_catalog
from spaghetti_extractor.util import sha256_file,write_json

HERE=Path(__file__).resolve().parent
PE_SHA256='191c113582e1f31016a158d40372fa21ea68d9348bf847bbfbc8e7c7bdfe195f'
RANGES=dict(fade=(0x2770,0x2a4a),right=(0x2a50,0x2af0),left=(0x2af0,0x2b95),rotate=(0x2ba0,0x2c03),set=(0x2c10,0x2c55))
ARGS=dict(fade=[('wait','u32'),('step','u32'),('first','u32'),('last','u32'),('direction','u32')],
    right=[('first','u32'),('last','u32'),('wrap','u32')],left=[('first','u32'),('last','u32'),('wrap','u32')],
    rotate=[('index','u32'),('count','u32'),('sequence','palette_sequence')],
    set=[('index','u32'),('red','u32'),('green','u32'),('blue','u32')])
OPS={n:[('state','palette_state'),*ARGS[n]] for n in RANGES}
PARAMETERS=dict(apply=[('state','palette_state'),('first','u32'),('count','u32')],wait=[('state','palette_state'),('count','u32')])
TYPES=[dict(id='unit',kind='void'),dict(id='u32',kind='integer',width_bits=32,signed=False),
    *[dict(id=n,kind='opaque',nominal_id='dxball.palette.'+n.removeprefix('palette_')) for n in ('palette_state','palette_sequence')]]
C_TYPES=dict(unit='void',u32='uint32_t',palette_state='palette_state *',palette_sequence='palette_sequence *')
NAMES=['fade-out','fade-in','already-black','already-staged','empty-range','windowed-fade','nonboolean-mode',
    'unused-direction','large-step','exact-step','zero-step-converged','zero-step-callback','negative-step-callback',
    'mode-change-during-fade','target-change-during-fade','right-wrap','left-wrap','right-black','left-black',
    'nonboolean-wrap','one-entry','whole-palette','windowed-shift','set-low-bytes','windowed-set',
    'rotate-three','rotate-four','rotate-sixty-six','windowed-rotate','rotate-callback','connected-effects']
CASES=[dict(id=n,arguments=[str(i)]) for i,n in enumerate(NAMES)]
SHARED=['pcx-state.h','flow-state.h','asset-state.h','font-state.h','cleanup-state.h']

def bridge_spec():
    return dict(adapters={n:dict(symbol='palette_'+n,kind='portable',context=True,outcomes={'return':None}) for n in PARAMETERS},transports={},native_symbol=None)

def bridge():
    text='#include "portable-component-implementation.h"\n#include "palette-runtime.h"\n#include "comparison-service-bridge.h"\n'
    for i,(n,p) in enumerate(OPS.items()):
        text+='void fixture_palette_'+n+'('+','.join(C_TYPES[t]+' '+a for a,t in p)+') {\n'
        text+=f'    palette_enter({i});spx_palette_effects_services_v5 services=spx_palette_effects_bind_services(NULL);\n    spx_palette_effects_context_v5 context={{0}};context.services=&services;spx_palette_effects_services_begin();\n'
        text+='    lifted_palette_'+n+'(&context,'+','.join(a for a,_ in p)+');spx_palette_effects_services_end();\n}\n'
    return text

def runtime_header():
    text='#ifndef DXBALL_PALETTE_RUNTIME_H\n#define DXBALL_PALETTE_RUNTIME_H\n#include "palette-state.h"\nvoid palette_enter(unsigned);\n'
    for n,p in OPS.items():text+='void fixture_palette_'+n+'('+','.join(C_TYPES[t] for _,t in p)+');\n'
    for n,p in PARAMETERS.items():text+='void palette_'+n+'(void *'+''.join(', '+C_TYPES[t] for _,t in p)+');\n'
    return text+'#endif\n'

def prepare(original,environment_package,output):
    from spaghetti_extractor.components.comparison_original import native_entry_header
    started=time.monotonic();output.mkdir(parents=True,exist_ok=False)
    if sha256_file(original)!=PE_SHA256:raise ValueError('requires pinned DX-Ball image')
    services={n:ServiceDefinition.create(identity='dxball.palette.'+n,types=TYPES,parameters=p,result='unit',resources=[],
        effects=['dxball.palette.'+n],outcomes=['return'],unobserved=['Readable and mutable shared storage, callback and progress premises in BOUNDARY.md.']) for n,p in PARAMETERS.items()}
    interface=component_interface(component_id='palette-effects',types=TYPES,services=services,
        operations={n:OperationDefinition(p,'unit',list(PARAMETERS) if n=='fade' else ['apply']) for n,p in OPS.items()})
    catalog=service_catalog(services).to_payload();write_json(output/'interface.json',interface.to_payload());write_json(output/'services.json',catalog);write_json(output/'bridge.json',bridge_spec())
    (output/'bridge.c').write_text(bridge());(output/'palette-runtime.h').write_text(runtime_header())
    sources={'palette.c':HERE/'palette.c','palette-state.h':HERE/'palette-state.h'}
    for name in SHARED:
        matches=list(environment_package.rglob(name))
        if not matches or len({sha256_file(p) for p in matches})!=1:raise ValueError('missing or inconsistent shared header '+name)
        sources[name]=matches[0]
    args=['component','start','dxball','palette-effects','--interface-intent',str(output/'interface.json'),
        '--service-catalog',str(output/'services.json'),'--service-bridge',str(output/'bridge.json'),
        '--assumption-file',str(HERE/'BOUNDARY.md'),'--remove-source','source/component.c','--output',str(output/'authoring')]
    for n in OPS:args+=['--operation-symbol',n+'=lifted_palette_'+n]
    for n,p in sources.items():args+=['--source-file','source/'+n+'='+str(p)]
    ran=subprocess.run([sys.executable,'-m','spaghetti_extractor',*args],capture_output=True,text=True)
    (output/'start.stdout').write_text(ran.stdout);(output/'start.stderr').write_text(ran.stderr)
    if ran.returncode:raise ValueError('inspect start.stderr')
    entries=dict(startup=(0xeaa0,0xeaa8),palette_wait=(0x2240,0x2248),**{'palette_'+n:r for n,r in RANGES.items()})
    (output/'native-image.h').write_text('\n'.join(native_entry_header(original=original,expected_sha256=PE_SHA256,module=None,
        entry_rva=lo,end_rva=hi,installer='install_'+n) for n,(lo,hi) in entries.items()))
    environment=native_environment(environment_package)
    prepare_comparison_package(interface_package=output/'authoring/interface.json',source_files={n:output/'authoring/source'/n for n in sources},
        operation_symbols={n:'lifted_palette_'+n for n in OPS},target_id='dxball',component_id='palette-effects',
        adapter_files={'runtime.c':HERE/'runtime.c','bridge.c':output/'bridge.c'},
        include_files={**observation_headers(),**native_adapter_headers('pe32-entry-hook.h'),
            'native-image.h':output/'native-image.h','palette-runtime.h':output/'palette-runtime.h'},
        **environment,original_files=['runtime/DXBall.exe'],oracle_kind='native-original',cases=CASES,
        observation_fields=['palette'],assumptions=[(HERE/'BOUNDARY.md').read_text()],
        scope='Shared palette fade, shifts, RGB update and rotating sequences used by actual scenes; original machine bodies and explicit callbacks.',
        service_catalog=catalog,service_bridge=bridge_spec(),export_adapters=['adapters/bridge.c'],
        program_driver=dict(kind='pe32-import',image='runtime/DXBall.exe',library='dx-palette.dll',symbol='dx_palette_anchor'),output=output/'palette-effects')
    write_json(output/'preparation.json',dict(seconds=time.monotonic()-started,cases=len(CASES),original_source_consulted=False,tool_internal_changes=False))

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for n in ('original','environment_package','output'):p.add_argument(n,type=Path)
    a=p.parse_args();prepare(a.original.resolve(),a.environment_package.resolve(),a.output.resolve())
