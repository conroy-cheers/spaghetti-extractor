"""Prepare native particle creation, movement and pixel drawing with ordinary C adapters."""
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
RANGES=dict(create=(0x7b00,0x7be5),update=(0x7bf0,0x7da6),draw=(0x7db0,0x7ea4))
OP_ARGS={name:[] for name in RANGES};OP_ARGS['create']=['x','y','dx','dy','color','gravity']
HOOKS=dict(allocate=0xdf40,free=0xdf30,terminate=0xe3d0,damage=0x1200)
PARAMETERS=dict(allocate=[('state','particle_state')],free=[('state','particle_state'),('item','particle')],
    terminate=[('state','particle_state'),('status','u32')],
    describe=[('state','particle_state'),('surface','cleanup_surface'),('view','pcx_view')],
    lock=[('state','particle_state'),('surface','cleanup_surface'),('view','pcx_view')],
    unlock=[('state','particle_state'),('surface','cleanup_surface')],
    damage=[('state','particle_state'),('bounds','font_rect')])
RESULTS={name:'u32' if name=='lock' else 'particle' if name=='allocate' else 'unit' for name in PARAMETERS}
TYPES=[dict(id='unit',kind='void'),dict(id='u32',kind='integer',width_bits=32,signed=False),
    *[dict(id=name,kind='opaque',nominal_id=nominal) for name,nominal in [('particle_state','dxball.particle.state'),
        ('particle','dxball.particle.object'),('font_rect','dxball.font.rect'),('cleanup_surface','dxball.cleanup.surface'),('pcx_view','dxball.pcx.view')]]]
C_TYPES=dict(unit='void',u32='uint32_t',particle_state='particle_state *',particle='particle *',font_rect='font_rect *',cleanup_surface='font_surface *',pcx_view='pcx_view *')
CASE_NAMES=['empty','creation-bounds','append-list','allocation-callback','allocation-failure-continuation',
    'motion','gravity-flags','signed-counters','motion-bounds','color-expiry','removal-skips-successor',
    'free-callback','draw-list','lock-retry','describe-callback','lock-callback','damage-callback',
    'destination-callback','color-bytes','generated-lifecycle']

def bridge_spec():
    return dict(adapters={name:dict(symbol='particle_'+name,kind='portable',context=True,outcomes={'return':None}) for name in PARAMETERS},transports={},native_symbol=None)

def bridge():
    text='#include "portable-component-implementation.h"\n#include "particle-runtime.h"\n#include "comparison-service-bridge.h"\n'
    for i,name in enumerate(RANGES):
        params=''.join(',uint32_t '+arg for arg in OP_ARGS[name]);args=''.join(','+arg for arg in OP_ARGS[name])
        text+=f'void fixture_particle_{name}(particle_state *state{params}) {{\n    particle_enter({i}); spx_particle_lifecycle_services_v5 services=spx_particle_lifecycle_bind_services(NULL);\n    spx_particle_lifecycle_context_v5 context={{0}}; context.services=&services; spx_particle_lifecycle_services_begin();\n'
        text+=f'    lifted_particle_{name}(&context,state{args}); spx_particle_lifecycle_services_end();\n}}\n'
    return text

def runtime_header():
    text='#ifndef DXBALL_PARTICLE_RUNTIME_H\n#define DXBALL_PARTICLE_RUNTIME_H\n#include "particle-state.h"\nvoid particle_enter(unsigned);\n'
    for name in RANGES:text+='void fixture_particle_'+name+'(particle_state *'+',uint32_t'*len(OP_ARGS[name])+');\n'
    for name,params in PARAMETERS.items():text+=C_TYPES[RESULTS[name]]+' particle_'+name+'(void *'+''.join(', '+C_TYPES[t] for _,t in params)+');\n'
    return text+'enum { '+', '.join('PARTICLE_'+name.upper()+'='+str(i) for i,name in enumerate(PARAMETERS))+' };\n#endif\n'

def prepare(original,shared_package,output):
    start=time.monotonic()
    if sha256_file(original)!=PE_SHA256:raise ValueError('requires pinned DX-Ball PE32')
    output.mkdir(parents=True,exist_ok=False)
    services={name:ServiceDefinition.create(identity='dxball.particle.'+name,types=TYPES,parameters=params,result=RESULTS[name],
        resources=[],effects=['dxball.particle.'+name],outcomes=['return'],unobserved=['Shared storage and ordered service effects in BOUNDARY.md; concrete comparisons, not checked heap summaries.']) for name,params in PARAMETERS.items()}
    interface=component_interface(component_id='particle-lifecycle',types=TYPES,services=services,
        operations={name:OperationDefinition([('state','particle_state')]+[(arg,'u32') for arg in OP_ARGS[name]],'unit',list(PARAMETERS)) for name in RANGES})
    catalog=service_catalog(services).to_payload()
    write_json(output/'interface.json',interface.to_payload());write_json(output/'services.json',catalog);write_json(output/'bridge.json',bridge_spec())
    (output/'bridge.c').write_text(bridge());(output/'particle-runtime.h').write_text(runtime_header())
    sources={'particle.c':HERE/'particle.c','particle-state.h':HERE/'particle-state.h'};pending=['pcx-state.h']
    while pending:
        name=pending.pop()
        if name in sources:continue
        path=shared_package/'source'/name
        if not path.is_file():raise ValueError('missing shared header '+name)
        sources[name]=path;pending+=re.findall(r'^#include "([^"]+)"',path.read_text(),re.MULTILINE)
    args=['component','start','dxball','particle-lifecycle','--interface-intent',str(output/'interface.json'),'--service-catalog',str(output/'services.json'),
        '--service-bridge',str(output/'bridge.json'),'--assumption-file',str(HERE/'BOUNDARY.md'),'--remove-source','source/component.c','--output',str(output/'authoring')]
    for name in RANGES:args+=['--operation-symbol',name+'=lifted_particle_'+name]
    for name,path in sources.items():args+=['--source-file','source/'+name+'='+str(path)]
    ran=subprocess.run([sys.executable,'-m','spaghetti_extractor',*args],capture_output=True,text=True)
    (output/'start.stdout').write_text(ran.stdout);(output/'start.stderr').write_text(ran.stderr)
    if ran.returncode:raise RuntimeError('inspect '+str(output/'start.stderr'))
    entries={**{'particle_'+n:r for n,r in RANGES.items()},'startup':(0xeaa0,0xeaa5),**{'particle_service_'+n:(r,r+8) for n,r in HOOKS.items()}}
    (output/'native-image.h').write_text('\n'.join(native_entry_header(original=original,expected_sha256=PE_SHA256,module=None,entry_rva=lo,end_rva=hi,installer='install_'+n) for n,(lo,hi) in entries.items()))
    environment=native_environment()
    prepare_comparison_package(interface_package=output/'authoring/interface.json',source_files={n:output/'authoring/source'/n for n in sources},
        operation_symbols={n:'lifted_particle_'+n for n in RANGES},target_id='dxball',component_id='particle-lifecycle',
        adapter_files={'runtime.c':HERE/'runtime.c','bridge.c':output/'bridge.c'},
        include_files={'native-image.h':output/'native-image.h','particle-runtime.h':output/'particle-runtime.h',
            **native_adapter_headers('pe32-entry-hook.h'),**observation_headers()},
        **{**environment,'runtime_files':{**environment['runtime_files'],'DXBall.exe':original}},original_files=['runtime/DXBall.exe'],oracle_kind='native-original',
        cases=[dict(id=n,arguments=[str(i)]) for i,n in enumerate(CASE_NAMES)],observation_fields=['particles'],
        assumptions=[(HERE/'BOUNDARY.md').read_text()],scope='Actual particle creation, movement, expiry and pixel drawing over linked objects and live surface views, without application startup.',
        service_catalog=catalog,service_bridge=bridge_spec(),export_adapters=['adapters/bridge.c'],
        program_driver=dict(kind='pe32-import',image='runtime/DXBall.exe',library='dx-particles.dll',symbol='dx_particles_anchor'),output=output/'particle-lifecycle')
    write_json(output/'preparation.json',dict(seconds=time.monotonic()-start,cases=len(CASE_NAMES),original_source_consulted=False,tool_internal_changes=False))

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('original','shared_package','output'):p.add_argument(name,type=Path)
    a=p.parse_args();prepare(a.original.resolve(),a.shared_package.resolve(),a.output.resolve())
