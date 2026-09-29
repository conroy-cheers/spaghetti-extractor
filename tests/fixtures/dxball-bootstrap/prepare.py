"""Prepare first-frame, initial-palette and clear bodies using retained inputs."""
import argparse
from pathlib import Path
import re
import subprocess
import sys
import time
from spaghetti_extractor.components.comparison_environment import native_environment,native_adapter_headers,observation_headers
from spaghetti_extractor.components.comparison_package import prepare_comparison_package
from spaghetti_extractor.components.service_authoring import OperationDefinition,ServiceDefinition,component_interface,service_catalog
from spaghetti_extractor.util import sha256_file,write_json

HERE=Path(__file__).resolve().parent
PE_SHA256='191c113582e1f31016a158d40372fa21ea68d9348bf847bbfbc8e7c7bdfe195f'
RANGES=dict(initialize=(0xad10,0xae1f),palette=(0x22b0,0x2313),clear=(0x2710,0x2761))
OPS={n:[('state','bootstrap_state'),*([('surface','cleanup_surface'),('color','u32')] if n=='clear' else [])] for n in RANGES}
ARGS=dict(create_overlay=[('device','shell_device'),('descriptor','display_surface')],terminate=[('code','u32')],
    scores_initialize=[],scores_load=[],boards_load=[('name','asset_name')],seed_random=[],now=[],
    vertical_blank=[('device','shell_device'),('flags','u32')],create_palette=[('device','shell_device'),('flags','u32')],
    attach_palette=[('surface','cleanup_surface'),('palette','shell_palette')],
    fill=[('surface','cleanup_surface'),('rectangle','font_rect'),('size','u32'),('flags','u32'),('color','u32')])
PARAMETERS={n:[('state','bootstrap_state'),*p] for n,p in ARGS.items()}
RESULTS={n:'u32' if n in ('create_overlay','create_palette','now') else 'unit' for n in PARAMETERS}
NOMINALS=dict(bootstrap_state='dxball.bootstrap.state',shell_device='dxball.application.device',shell_palette='dxball.application.palette',
    display_surface='dxball.display.surface',cleanup_surface='dxball.cleanup.surface',font_rect='dxball.font.rect',asset_name='dxball.asset.name')
TYPES=[dict(id='unit',kind='void'),dict(id='u32',kind='integer',width_bits=32,signed=False),
    *[dict(id=n,kind='opaque',nominal_id=v) for n,v in NOMINALS.items()]]
C_TYPES=dict(unit='void',u32='uint32_t',**{n:n+' *' for n in NOMINALS});C_TYPES['cleanup_surface']='font_surface *'
NAMES=['initialize','refresh-399','refresh-400','refresh-401','refresh-wrap','fast-one','fast-two','no-hardware','nonboolean-hardware',
    'overlay-negative-unpublished','overlay-positive-published','overlay-negative-published','palette-negative-unpublished',
    'palette-positive-published','palette-negative-published','overlay-callback','scores-callback','boards-callback','palette-callback',
    'vblank-callback','clock-callback','palette-only','palette-only-negative','palette-only-positive','palette-only-callback',
    'clear','clear-full-color','clear-callback-error','connected-bootstrap']
CASES=[dict(id=n,arguments=[str(i)]) for i,n in enumerate(NAMES)]

def bridge_spec():
    return dict(adapters={n:dict(symbol='bootstrap_'+n,kind='portable',context=True,outcomes={'return':None}) for n in PARAMETERS},transports={},native_symbol=None)

def bridge():
    text='#include "portable-component-implementation.h"\n#include "bootstrap-runtime.h"\n#include "comparison-service-bridge.h"\n'
    for i,(n,p) in enumerate(OPS.items()):
        text+='void fixture_bootstrap_'+n+'('+','.join(C_TYPES[t]+' '+a for a,t in p)+') {\n'
        text+=f'    bootstrap_enter({i});spx_application_bootstrap_services_v5 services=spx_application_bootstrap_bind_services(NULL);\n    spx_application_bootstrap_context_v5 context={{0}};context.services=&services;spx_application_bootstrap_services_begin();\n'
        text+='    lifted_bootstrap_'+n+'(&context,'+','.join(a for a,_ in p)+');spx_application_bootstrap_services_end();\n}\n'
    return text

def runtime_header():
    text='#ifndef DXBALL_BOOTSTRAP_RUNTIME_H\n#define DXBALL_BOOTSTRAP_RUNTIME_H\n#include "bootstrap-state.h"\nvoid bootstrap_enter(unsigned);\n'
    for n,p in OPS.items():text+='void fixture_bootstrap_'+n+'('+','.join(C_TYPES[t] for _,t in p)+');\n'
    for n,p in PARAMETERS.items():text+=C_TYPES[RESULTS[n]]+' bootstrap_'+n+'(void *'+''.join(', '+C_TYPES[t] for _,t in p)+');\n'
    return text+'enum { '+', '.join('BOOTSTRAP_SERVICE_'+n.upper()+'='+str(i) for i,n in enumerate(PARAMETERS))+' };\n#endif\n'

def prepare(original,environment_package,output):
    from spaghetti_extractor.components.comparison_original import native_entry_header
    started=time.monotonic();output.mkdir(parents=True,exist_ok=False)
    if sha256_file(original)!=PE_SHA256:raise ValueError('requires pinned DX-Ball image')
    services={n:ServiceDefinition.create(identity='dxball.bootstrap.'+n,types=TYPES,parameters=p,result=RESULTS[n],resources=[],
        effects=['dxball.bootstrap.'+n],outcomes=['return'],nonlocal_outcomes=['process-exit'] if n=='terminate' else [],
        unobserved=['Defined descriptor fields, stable roots, shared storage and resource lifetime premises in BOUNDARY.md.']) for n,p in PARAMETERS.items()}
    used=dict(initialize=list(PARAMETERS),palette=['create_palette','attach_palette'],clear=['fill'])
    interface=component_interface(component_id='application-bootstrap',types=TYPES,services=services,
        operations={n:OperationDefinition(p,'unit',used[n]) for n,p in OPS.items()})
    catalog=service_catalog(services).to_payload();write_json(output/'interface.json',interface.to_payload());write_json(output/'services.json',catalog);write_json(output/'bridge.json',bridge_spec())
    (output/'bridge.c').write_text(bridge());(output/'bootstrap-runtime.h').write_text(runtime_header())
    sources={'bootstrap.c':HERE/'bootstrap.c','bootstrap-state.h':HERE/'bootstrap-state.h'};pending=['display-state.h']
    while pending:
        name=pending.pop()
        if name in sources:continue
        matches=list(environment_package.rglob(name))
        if not matches or len({sha256_file(p) for p in matches})!=1:raise ValueError('missing or inconsistent shared header '+name)
        sources[name]=matches[0];pending+=re.findall(r'^#include "([^"]+)"',matches[0].read_text(),re.MULTILINE)
    args=['component','start','dxball','application-bootstrap','--interface-intent',str(output/'interface.json'),
        '--service-catalog',str(output/'services.json'),'--service-bridge',str(output/'bridge.json'),
        '--assumption-file',str(HERE/'BOUNDARY.md'),'--remove-source','source/component.c','--output',str(output/'authoring')]
    for n in OPS:args+=['--operation-symbol',n+'=lifted_bootstrap_'+n]
    for n,p in sources.items():args+=['--source-file','source/'+n+'='+str(p)]
    ran=subprocess.run([sys.executable,'-m','spaghetti_extractor',*args],capture_output=True,text=True)
    (output/'start.stdout').write_text(ran.stdout);(output/'start.stderr').write_text(ran.stderr)
    if ran.returncode:raise ValueError('inspect start.stderr')
    services_rva=dict(scores_initialize=0x9bb0,scores_load=0x9a30,boards_load=0x3d50,seed_random=0xae30,now=0xdb20,terminate=0xe3d0)
    entries=dict(startup=(0xeaa0,0xeaa8),**{'bootstrap_'+n:r for n,r in RANGES.items()},
        **{'bootstrap_'+n:(r,r+8) for n,r in services_rva.items()})
    (output/'native-image.h').write_text('\n'.join(native_entry_header(original=original,expected_sha256=PE_SHA256,module=None,
        entry_rva=lo,end_rva=hi,installer='install_'+n) for n,(lo,hi) in entries.items()))
    prepare_comparison_package(interface_package=output/'authoring/interface.json',source_files={n:output/'authoring/source'/n for n in sources},
        operation_symbols={n:'lifted_bootstrap_'+n for n in OPS},target_id='dxball',component_id='application-bootstrap',
        adapter_files={'runtime.c':HERE/'runtime.c','bridge.c':output/'bridge.c'},
        include_files={**observation_headers(),**native_adapter_headers('pe32-entry-hook.h'),
            'native-image.h':output/'native-image.h','bootstrap-runtime.h':output/'bootstrap-runtime.h'},
        **native_environment(environment_package),original_files=['runtime/DXBall.exe'],oracle_kind='native-original',cases=CASES,
        observation_fields=['bootstrap'],assumptions=[(HERE/'BOUNDARY.md').read_text()],
        scope='First-frame initialization, initial palette creation and surface clear; exact machine bodies with explicit mutable resource and timing services.',
        service_catalog=catalog,service_bridge=bridge_spec(),export_adapters=['adapters/bridge.c'],
        program_driver=dict(kind='pe32-import',image='runtime/DXBall.exe',library='dx-bootstrap.dll',symbol='dx_bootstrap_anchor'),output=output/'application-bootstrap')
    write_json(output/'preparation.json',dict(seconds=time.monotonic()-started,cases=len(CASES),original_source_consulted=False,tool_internal_changes=False))

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for n in ('original','environment_package','output'):p.add_argument(n,type=Path)
    a=p.parse_args();prepare(a.original.resolve(),a.environment_package.resolve(),a.output.resolve())
