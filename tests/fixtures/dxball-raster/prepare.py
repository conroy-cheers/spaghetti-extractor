"""Prepare complete raster bodies with shared DirectDraw platform observation."""
import argparse
from pathlib import Path
import re
import subprocess
import sys
import time
from spaghetti_extractor.components.comparison_environment import native_environment,native_adapter_headers,observation_headers
from spaghetti_extractor.components.comparison_package import prepare_comparison_package
from spaghetti_extractor.components.comparison_wine_environment import wine_test_backend
from spaghetti_extractor.components.service_authoring import OperationDefinition,ServiceDefinition,component_interface,service_catalog
from spaghetti_extractor.util import sha256_file,write_json

HERE=Path(__file__).resolve().parent
PE_SHA256='191c113582e1f31016a158d40372fa21ea68d9348bf847bbfbc8e7c7bdfe195f'
RANGES=dict(line=(0xd850,0xd981),fill=(0xd990,0xd9f0))
OPS={n:[('surface','cleanup_surface'),*[(p,'u32') for p in ('x1','y1','x2','y2','color')]] for n in RANGES}
PARAMETERS=dict(describe=[('surface','cleanup_surface'),('view','pcx_view')],lock=[('surface','cleanup_surface'),('view','pcx_view')],
    unlock=[('surface','cleanup_surface')],fill=[('surface','cleanup_surface'),('rectangle','font_rect'),('size','u32'),('flags','u32'),('color','u32')])
NOMINALS=dict(cleanup_surface='dxball.cleanup.surface',pcx_view='dxball.pcx.view',font_rect='dxball.font.rect')
TYPES=[dict(id='unit',kind='void'),dict(id='u32',kind='integer',width_bits=32,signed=False),
    *[dict(id=n,kind='opaque',nominal_id=v) for n,v in NOMINALS.items()]]
C_TYPES=dict(unit='void',u32='uint32_t',cleanup_surface='font_surface *',pcx_view='pcx_view *',font_rect='font_rect *')
NAMES=['octants','horizontal-color','vertical','point','strict-thresholds','diagonals','negative-pitch','wrapped-padding',
    'post-lock-pitch','failed-description','lock-retries','positive-lock-status','unlock-error','shared-callback',
    'wrapped-deltas','full-color-fill','invalid-fill-failure','connected-surfaces']
CASES=[dict(id=n,arguments=[str(i)]) for i,n in enumerate(NAMES)]

def bridge_spec():
    return dict(adapters={n:dict(symbol='raster_'+n,kind='portable',context=True,outcomes={'return':None}) for n in PARAMETERS},transports={},native_symbol=None)

def bridge():
    text='#include "portable-component-implementation.h"\n#include "raster-runtime.h"\n#include "comparison-service-bridge.h"\n'
    for i,(n,p) in enumerate(OPS.items()):
        text+='void fixture_raster_'+n+'('+','.join(C_TYPES[t]+' '+a for a,t in p)+') {\n'
        text+=f'    raster_enter({i});spx_raster_drawing_services_v5 services=spx_raster_drawing_bind_services(NULL);\n    spx_raster_drawing_context_v5 context={{0}};context.services=&services;spx_raster_drawing_services_begin();\n'
        text+='    lifted_raster_'+n+'(&context,'+','.join(a for a,_ in p)+');spx_raster_drawing_services_end();\n}\n'
    return text

def runtime_header():
    text='#ifndef DXBALL_RASTER_RUNTIME_H\n#define DXBALL_RASTER_RUNTIME_H\n#include "pcx-state.h"\nvoid raster_enter(unsigned);\n'
    for n,p in OPS.items():text+='void fixture_raster_'+n+'('+','.join(C_TYPES[t] for _,t in p)+');\n'
    for n,p in PARAMETERS.items():text+='uint32_t raster_'+n+'(void *'+''.join(', '+C_TYPES[t] for _,t in p)+');\n'
    return text+'#endif\n'

def prepare(original,environment_package,output):
    from spaghetti_extractor.components.comparison_original import native_entry_header
    started=time.monotonic();output.mkdir(parents=True,exist_ok=False)
    if sha256_file(original)!=PE_SHA256:raise ValueError('requires pinned DX-Ball image')
    services={n:ServiceDefinition.create(identity='dxball.raster.'+n,types=TYPES,parameters=p,result='u32',resources=[],
        effects=['dxball.raster.'+n],outcomes=['return'],unobserved=['Shared surface storage and descriptor fields consumed by API flags; see BOUNDARY.md.']) for n,p in PARAMETERS.items()}
    interface=component_interface(component_id='raster-drawing',types=TYPES,services=services,
        operations={n:OperationDefinition(p,'unit',['fill'] if n=='fill' else ['describe','lock','unlock']) for n,p in OPS.items()})
    catalog=service_catalog(services).to_payload();write_json(output/'interface.json',interface.to_payload());write_json(output/'services.json',catalog);write_json(output/'bridge.json',bridge_spec())
    (output/'bridge.c').write_text(bridge());(output/'raster-runtime.h').write_text(runtime_header())
    sources={'raster.c':HERE/'raster.c'};pending=['pcx-state.h']
    while pending:
        name=pending.pop()
        if name in sources:continue
        matches=list(environment_package.rglob(name))
        if not matches or len({sha256_file(p) for p in matches})!=1:raise ValueError('missing or inconsistent shared header '+name)
        sources[name]=matches[0];pending+=re.findall(r'^#include "([^"]+)"',matches[0].read_text(),re.MULTILINE)
    args=['component','start','dxball','raster-drawing','--interface-intent',str(output/'interface.json'),
        '--service-catalog',str(output/'services.json'),'--service-bridge',str(output/'bridge.json'),
        '--assumption-file',str(HERE/'BOUNDARY.md'),'--remove-source','source/component.c','--output',str(output/'authoring')]
    for n in OPS:args+=['--operation-symbol',n+'=lifted_raster_'+n]
    for n,p in sources.items():args+=['--source-file','source/'+n+'='+str(p)]
    ran=subprocess.run([sys.executable,'-m','spaghetti_extractor',*args],capture_output=True,text=True)
    (output/'start.stdout').write_text(ran.stdout);(output/'start.stderr').write_text(ran.stderr)
    if ran.returncode:raise ValueError('inspect start.stderr')
    entries=dict(startup=(0xeaa0,0xeaa8),**{'raster_'+n:r for n,r in RANGES.items()})
    (output/'native-image.h').write_text('\n'.join(native_entry_header(original=original,expected_sha256=PE_SHA256,module=None,
        entry_rva=lo,end_rva=hi,installer='install_'+n) for n,(lo,hi) in entries.items()))
    backend=wine_test_backend()
    prepare_comparison_package(interface_package=output/'authoring/interface.json',source_files={n:output/'authoring/source'/n for n in sources},
        operation_symbols={n:'lifted_raster_'+n for n in OPS},target_id='dxball',component_id='raster-drawing',
        adapter_files={**backend['adapter_files'],'runtime.c':HERE/'runtime.c','bridge.c':output/'bridge.c'},
        include_files={**backend['include_files'],**observation_headers(),**native_adapter_headers('pe32-entry-hook.h'),
            'native-image.h':output/'native-image.h','raster-runtime.h':output/'raster-runtime.h'},
        **native_environment(environment_package),original_files=['runtime/DXBall.exe'],oracle_kind='native-original',cases=CASES,
        observation_fields=['platform'],assumptions=[(HERE/'BOUNDARY.md').read_text()],
        scope='Complete line/fill bodies with shared DirectDraw surfaces, signed/wrapping offsets, whole backing storage and API outcomes.',
        service_catalog=catalog,service_bridge=bridge_spec(),export_adapters=['adapters/bridge.c'],
        program_driver=dict(kind='pe32-import',image='runtime/DXBall.exe',library='dx-raster.dll',symbol='dx_raster_anchor'),output=output/'raster-drawing')
    write_json(output/'preparation.json',dict(seconds=time.monotonic()-started,cases=len(CASES),original_source_consulted=False,tool_internal_changes=False))

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for n in ('original','environment_package','output'):p.add_argument(n,type=Path)
    a=p.parse_args();prepare(a.original.resolve(),a.environment_package.resolve(),a.output.resolve())
