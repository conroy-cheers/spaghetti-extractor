"""Author the binary-derived score table with byte-faithful file services."""
import argparse
from pathlib import Path
import subprocess
import sys
import time

import pefile

from spaghetti_extractor.components.comparison_environment import native_adapter_headers, native_environment, observation_headers
from spaghetti_extractor.components.comparison_original import native_entry_header
from spaghetti_extractor.components.comparison_package import prepare_comparison_package
from spaghetti_extractor.components.service_authoring import OperationDefinition, ServiceDefinition, component_interface, service_catalog
from spaghetti_extractor.util import sha256_file, write_json

HERE=Path(__file__).resolve().parent
PE_SHA256='191c113582e1f31016a158d40372fa21ea68d9348bf847bbfbc8e7c7bdfe195f'
RANGES=dict(load=(0x9a30,0x9a6c),initialize=(0x9bb0,0x9f7e),insert=(0x9a70,0x9bac))
PARAMETERS=dict(load=[('state','scores_state')],initialize=[('state','scores_state')],
    insert=[('state','scores_state'),('name','scores_name'),('value','u32')])
SERVICES=dict(open=[('state','scores_state'),('write','u32')],
    read=[('state','scores_state'),('file','scores_file'),('bytes','scores_bytes')],
    write=[('state','scores_state'),('file','scores_file'),('bytes','scores_bytes')],
    close=[('state','scores_state'),('file','scores_file')],access=[('state','scores_state'),('mode','u32')])
RESULTS=dict(open='scores_file',access='u32')
TYPES=[dict(id='unit',kind='void'),dict(id='u32',kind='integer',signed=False,width_bits=32),
    *[dict(id='scores_'+name,kind='opaque',nominal_id='dxball.scores.'+name) for name in ('state','file','name','bytes')]]
C_TYPES=dict(unit='void',u32='uint32_t',**{'scores_'+name:'scores_'+name+' *' for name in ('state','file','name','bytes')})
HOOKS=dict(open=(0xe190,0xe1a5),read=(0xe580,0xe590),write=(0xe6c0,0xe6d0),close=(0xdf50,0xdf58),access=(0xe810,0xe820))


def bridge_spec():
    return dict(adapters={name:dict(symbol='scores_'+name,kind='portable',context=True,outcomes={'return':None})
        for name in SERVICES},transports={},native_symbol=None)


def bridge():
    text='#include "portable-component-implementation.h"\n#include "scores-runtime.h"\n#include "comparison-service-bridge.h"\n'
    for index,(name,parameters) in enumerate(PARAMETERS.items()):
        result='uint32_t' if name=='insert' else 'void'
        signature=', '.join(C_TYPES[kind]+' '+key for key,kind in parameters)
        args=', '.join(key for key,_ in parameters)
        call=('uint32_t result=' if name=='insert' else '')+f'lifted_scores_{name}(&context,{args});'
        text+=f'''{result} fixture_scores_{name}({signature}) {{
    scores_enter({index}); spx_score_table_services_v5 services=spx_score_table_bind_services(NULL);
    spx_score_table_context_v5 context={{0}}; context.services=&services;
    spx_score_table_services_begin(); {call} spx_score_table_services_end();
    {"return result;" if name=="insert" else ""}
}}
'''
    return text


def runtime_header():
    text='#ifndef DXBALL_SCORES_RUNTIME_H\n#define DXBALL_SCORES_RUNTIME_H\n#include "scores-state.h"\nvoid scores_enter(unsigned);\n'
    for name,parameters in PARAMETERS.items():
        text+=('uint32_t' if name=='insert' else 'void')+' fixture_scores_'+name+'('+', '.join(C_TYPES[t] for _,t in parameters)+');\n'
    for name,parameters in SERVICES.items():
        text+=C_TYPES[RESULTS.get(name,'unit')]+' scores_'+name+'(void *'+''.join(', '+C_TYPES[t] for _,t in parameters)+');\n'
    return text+'#endif\n'


def data_header(original):
    image=pefile.PE(str(original)); addresses=[0x416884,0x41685c,0x41683c,0x416814,0x4167ec,0x4167c4,
        0x41679c,0x41677c,0x416758,0x41673c,0x416714,0x4166ec,0x4166c8,0x416714,0x416714]
    names=[image.get_data(address-0x400000,40).split(b'\0')[0] for address in addresses]
    if any(len(name)>=40 for name in names):raise ValueError('default score name exceeds record')
    return '/* Literal names from the pinned executable. */\nstatic const char scores_default_names[15][40]={\n'+\
        ''.join('    {'+','.join(str(b) for b in name)+',0},\n' for name in names)+'};\n'


def cases():
    names=['existing-defaults','create-defaults','unusual-access-result','failed-create','failed-read-open',
        'empty-read','one-byte-read','partial-score-word','complete-read','below-minimum','equal-minimum',
        'middle-score','equal-maximum','unsigned-maximum','write-access-denied','failed-write-open',
        'short-write','partial-last-record','retained-real-file','unsorted-table']
    return [dict(id=name,arguments=[str(i)]) for i,name in enumerate(names)]


def prepare(original,score_file,output):
    started=time.monotonic()
    if sha256_file(original)!=PE_SHA256:raise ValueError('requires pinned DX-Ball PE32')
    output.mkdir(parents=True,exist_ok=False)
    definitions={name:ServiceDefinition.create(identity='dxball.scores.'+name,types=TYPES,parameters=parameters,
        result=RESULTS.get(name,'unit'),resources=[],effects=['dxball.scores.'+name],outcomes=['return'],nullable_result=name=='open',
        unobserved=['Explicit file lifecycle, byte transfer and nonreentrant service domain in BOUNDARY.md.']) for name,parameters in SERVICES.items()}
    used=dict(load=['open','read','close'],initialize=['access','open','write','close'],insert=list(SERVICES))
    interface=component_interface(component_id='score-table',types=TYPES,services=definitions,
        operations={name:OperationDefinition(parameters,'u32' if name=='insert' else 'unit',used[name]) for name,parameters in PARAMETERS.items()})
    catalog=service_catalog(definitions).to_payload()
    write_json(output/'interface.json',interface.to_payload());write_json(output/'services.json',catalog)
    write_json(output/'bridge.json',bridge_spec());(output/'bridge.c').write_text(bridge())
    (output/'scores-runtime.h').write_text(runtime_header());(output/'scores-data.h').write_text(data_header(original))
    sources={'scores.c':HERE/'scores.c','scores-state.h':HERE/'scores-state.h','scores-data.h':output/'scores-data.h'}
    args=['component','start','dxball','score-table','--interface-intent',str(output/'interface.json'),
        '--service-catalog',str(output/'services.json'),'--service-bridge',str(output/'bridge.json'),
        '--assumption-file',str(HERE/'BOUNDARY.md'),'--remove-source','source/component.c','--output',str(output/'authoring')]
    for name in PARAMETERS:args+=['--operation-symbol',name+'=lifted_scores_'+name]
    for name,path in sources.items():args+=['--source-file','source/'+name+'='+str(path)]
    ran=subprocess.run([sys.executable,'-m','spaghetti_extractor',*args],capture_output=True,text=True)
    (output/'start.stdout').write_text(ran.stdout);(output/'start.stderr').write_text(ran.stderr)
    if ran.returncode:raise RuntimeError('inspect '+str(output/'start.stderr'))
    entries={**{'scores_'+name:span for name,span in RANGES.items()},**{'scores_service_'+name:span for name,span in HOOKS.items()},'startup':(0xeaa0,0xeaa5)}
    (output/'native-image.h').write_text('\n'.join(native_entry_header(original=original,expected_sha256=PE_SHA256,
        module=None,entry_rva=lo,end_rva=hi,installer='install_'+name) for name,(lo,hi) in entries.items()))
    environment=native_environment()
    prepare_comparison_package(interface_package=output/'authoring/interface.json',source_files={name:output/'authoring/source'/name for name in sources},
        operation_symbols={name:'lifted_scores_'+name for name in PARAMETERS},target_id='dxball',component_id='score-table',
        adapter_files={'runtime.c':HERE/'runtime.c','bridge.c':output/'bridge.c'},
        include_files={'scores-runtime.h':output/'scores-runtime.h','native-image.h':output/'native-image.h',
            **native_adapter_headers('pe32-entry-hook.h'),**observation_headers()},
        **{**environment,'runtime_files':{**environment['runtime_files'],'DXBall.exe':original,'score.dat':score_file}},
        original_files=['runtime/DXBall.exe'],oracle_kind='native-original',cases=cases(),
        observation_fields=['states','services','file','file_size','rank'],assumptions=[(HERE/'BOUNDARY.md').read_text()],
        scope='Persistent score records: exact bytes and padding, unsigned insertion, partial I/O, access/open failures and file lifecycle.',
        service_catalog=catalog,service_bridge=bridge_spec(),export_adapters=['adapters/bridge.c'],
        program_driver=dict(kind='pe32-import',image='runtime/DXBall.exe',library='dx-scores.dll',symbol='dx_scores_anchor'),
        output=output/'score-table')
    write_json(output/'preparation.json',dict(seconds=time.monotonic()-started,cases=len(cases()),original_source_consulted=False,tool_internal_changes=False))


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('original','score_file','output'):parser.add_argument(name,type=Path)
    a=parser.parse_args();prepare(a.original.resolve(),a.score_file.resolve(),a.output.resolve())
