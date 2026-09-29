"""Prepare clock, refresh wait and random bodies using retained inputs."""
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
RANGES=dict(clock_init=(0xdba0,0xdbd2),now=(0xdb20,0xdb7b),elapsed=(0xdb80,0xdb9f),wait=(0x2240,0x22a4),
    set_seed=(0xea60,0xea6a),next=(0xea70,0xea9a),random=(0xae20,0xae2d),seed=(0xae30,0xae49))
OP_ARGS=dict(clock_init=[('platform_history','u32')],now=[('history','runtime_sample')],elapsed=[('previous','u32'),('delay','u32')],
    wait=[('count','u32')],set_seed=[('seed','u32')],next=[],random=[('limit','u32')],seed=[])
OPS={n:[('state','runtime_state'),*OP_ARGS[n]] for n in RANGES}
OP_RESULTS={n:'u32' if n in ('now','elapsed','next','random') else 'unit' for n in RANGES}
ARGS=dict(version=[('version','runtime_version')],frequency=[('value','runtime_sample')],counter=[('value','runtime_sample')],
    ticks=[],now=[],vertical_blank=[('device','shell_device'),('flags','u32')],fault=[('code','u32')])
PARAMETERS={n:[('state','runtime_state'),*p] for n,p in ARGS.items()}
RESULTS={n:'u32' if n in ('frequency','ticks','now') else 'unit' for n in PARAMETERS}
NOMINALS=dict(runtime_state='dxball.runtime.state',runtime_sample='dxball.runtime.sample',runtime_version='dxball.runtime.version',shell_device='dxball.application.device')
TYPES=[dict(id='unit',kind='void'),dict(id='u32',kind='integer',width_bits=32,signed=False),
    *[dict(id=n,kind='opaque',nominal_id=v) for n,v in NOMINALS.items()]]
C_TYPES=dict(unit='void',u32='uint32_t',**{n:n+' *' for n in NOMINALS});C_TYPES['runtime_version']='runtime_version_query *'
NAMES=['now-fallback','now-counter','frequency-cache','frequency-failed','frequency-high-ignored','counter-high-ignored',
    'counter-unwritten-history','counter-unwritten-frequency','frequency-partial','counter-partial','frequency-callback',
    'counter-callback-divisor','counter-zero-divisor','frequency-zero-divisor','initialize-modern','initialize-legacy',
    'initialize-nonboolean','initialize-unwritten-history','initialize-failed-publication','elapsed-before','elapsed-equal',
    'elapsed-after','elapsed-backward','elapsed-addition-wrap','elapsed-zero-delay','wait-vertical','wait-zero','wait-negative',
    'wait-vertical-callback','wait-poll','wait-poll-multiple','wait-backward','wait-addition-wrap','wait-clock-callback',
    'generator-sequences','seed-clock','seed-wrap','seed-callback','random-positive','random-negative','random-int-min',
    'random-one','random-zero-fault','seed-then-next','repeated-counter-reads','frequency-positive-status']
CASES=[dict(id=n,arguments=[str(i)]) for i,n in enumerate(NAMES)]

def bridge_spec():
    return dict(adapters={n:dict(symbol='runtime_'+n,kind='portable',context=True,outcomes={'return':None}) for n in PARAMETERS},transports={},native_symbol=None)

def bridge():
    text='#include "portable-component-implementation.h"\n#include "runtime-support.h"\n#include "comparison-service-bridge.h"\n'
    for i,(n,p) in enumerate(OPS.items()):
        text+=C_TYPES[OP_RESULTS[n]]+' fixture_runtime_'+n+'('+','.join(C_TYPES[t]+' '+a for a,t in p)+') {\n'
        text+=f'    runtime_enter({i});spx_runtime_support_services_v5 services=spx_runtime_support_bind_services(NULL);\n    spx_runtime_support_context_v5 context={{0}};context.services=&services;spx_runtime_support_services_begin();\n'
        text+='    '+('uint32_t result=' if OP_RESULTS[n]!='unit' else '')+'lifted_runtime_'+n+'(&context,'+','.join(a for a,_ in p)+');spx_runtime_support_services_end();'+('return result;' if OP_RESULTS[n]!='unit' else '')+'\n}\n'
    return text

def runtime_header():
    text='#ifndef DXBALL_RUNTIME_SUPPORT_H\n#define DXBALL_RUNTIME_SUPPORT_H\n#include "runtime-state.h"\nvoid runtime_enter(unsigned);\n'
    for n,p in OPS.items():text+=C_TYPES[OP_RESULTS[n]]+' fixture_runtime_'+n+'('+','.join(C_TYPES[t] for _,t in p)+');\n'
    for n,p in PARAMETERS.items():text+=C_TYPES[RESULTS[n]]+' runtime_'+n+'(void *'+''.join(', '+C_TYPES[t] for _,t in p)+');\n'
    return text+'enum { '+', '.join('RUNTIME_SERVICE_'+n.upper()+'='+str(i) for i,n in enumerate(PARAMETERS))+' };\n#endif\n'

def prepare(original,environment_package,output):
    from spaghetti_extractor.components.comparison_original import native_entry_header
    started=time.monotonic();output.mkdir(parents=True,exist_ok=False)
    if sha256_file(original)!=PE_SHA256:raise ValueError('requires pinned DX-Ball image')
    services={n:ServiceDefinition.create(identity='dxball.runtime.'+n,types=TYPES,parameters=p,result=RESULTS[n],resources=[],
        effects=['dxball.runtime.'+n],outcomes=['return'],nonlocal_outcomes=['arithmetic-fault'] if n=='fault' else [],
        unobserved=['Clock storage history, low-word arithmetic, shared state callbacks, resource lifetime and progress premises in BOUNDARY.md.']) for n,p in PARAMETERS.items()}
    used=dict(clock_init=['version'],now=['frequency','counter','ticks','fault'],elapsed=['now'],wait=['now','vertical_blank'],set_seed=[],next=[],random=['fault'],seed=['ticks'])
    interface=component_interface(component_id='runtime-support',types=TYPES,services=services,
        operations={n:OperationDefinition(p,OP_RESULTS[n],used[n]) for n,p in OPS.items()})
    catalog=service_catalog(services).to_payload();write_json(output/'interface.json',interface.to_payload());write_json(output/'services.json',catalog);write_json(output/'bridge.json',bridge_spec())
    (output/'bridge.c').write_text(bridge());(output/'runtime-support.h').write_text(runtime_header())
    sources={n:HERE/n for n in ['clock.c','random.c','runtime-state.h']};pending=['bootstrap-state.h']
    while pending:
        name=pending.pop()
        if name in sources:continue
        matches=list(environment_package.rglob(name))
        if not matches or len({sha256_file(p) for p in matches})!=1:raise ValueError('missing or inconsistent shared header '+name)
        sources[name]=matches[0];pending+=re.findall(r'^#include "([^"]+)"',matches[0].read_text(),re.MULTILINE)
    args=['component','start','dxball','runtime-support','--interface-intent',str(output/'interface.json'),
        '--service-catalog',str(output/'services.json'),'--service-bridge',str(output/'bridge.json'),
        '--assumption-file',str(HERE/'BOUNDARY.md'),'--remove-source','source/component.c','--output',str(output/'authoring')]
    for n in OPS:args+=['--operation-symbol',n+'=lifted_runtime_'+n]
    for n,p in sources.items():args+=['--source-file','source/'+n+'='+str(p)]
    ran=subprocess.run([sys.executable,'-m','spaghetti_extractor',*args],capture_output=True,text=True)
    (output/'start.stdout').write_text(ran.stdout);(output/'start.stderr').write_text(ran.stderr)
    if ran.returncode:raise ValueError('inspect start.stderr')
    entries=dict(startup=(0xeaa0,0xeaa8),**{'runtime_'+n:r for n,r in RANGES.items()})
    (output/'native-image.h').write_text('\n'.join(native_entry_header(original=original,expected_sha256=PE_SHA256,module=None,
        entry_rva=lo,end_rva=hi,installer='install_'+n) for n,(lo,hi) in entries.items()))
    prepare_comparison_package(interface_package=output/'authoring/interface.json',source_files={n:output/'authoring/source'/n for n in sources},
        operation_symbols={n:'lifted_runtime_'+n for n in OPS},target_id='dxball',component_id='runtime-support',
        adapter_files={'runtime.c':HERE/'runtime.c','bridge.c':output/'bridge.c'},
        include_files={**observation_headers(),**native_adapter_headers('pe32-entry-hook.h','pe32-import-hook.h'),
            'native-image.h':output/'native-image.h','runtime-support.h':output/'runtime-support.h'},
        **native_environment(environment_package),original_files=['runtime/DXBall.exe'],oracle_kind='native-original',cases=CASES,
        observation_fields=['runtime'],assumptions=[(HERE/'BOUNDARY.md').read_text()],
        scope='Clock setup/read, wrapping elapsed and wait policy, and shared random state; complete machine bodies with explicit history, platform services and arithmetic fault outcomes.',
        service_catalog=catalog,service_bridge=bridge_spec(),export_adapters=['adapters/bridge.c'],
        program_driver=dict(kind='pe32-import',image='runtime/DXBall.exe',library='dx-runtime.dll',symbol='dx_runtime_anchor'),output=output/'runtime-support')
    write_json(output/'preparation.json',dict(seconds=time.monotonic()-started,cases=len(CASES),original_source_consulted=False,tool_internal_changes=False))

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for n in ('original','environment_package','output'):p.add_argument(n,type=Path)
    a=p.parse_args();prepare(a.original.resolve(),a.environment_package.resolve(),a.output.resolve())
