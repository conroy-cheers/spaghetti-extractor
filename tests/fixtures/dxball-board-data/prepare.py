"""Author binary-derived board storage and sprite mapping through public interfaces."""
import argparse
from pathlib import Path
import struct
import subprocess
import sys
import time

import pefile

from spaghetti_extractor.components.comparison_environment import native_adapter_headers,native_environment,observation_headers
from spaghetti_extractor.components.comparison_original import native_entry_header
from spaghetti_extractor.components.comparison_package import prepare_comparison_package
from spaghetti_extractor.components.service_authoring import OperationDefinition,ServiceDefinition,component_interface,service_catalog
from spaghetti_extractor.util import sha256_file,write_json

HERE=Path(__file__).resolve().parent
PE_SHA256='191c113582e1f31016a158d40372fa21ea68d9348bf847bbfbc8e7c7bdfe195f'
RANGES=dict(load=(0x3d50,0x3d90),save=(0x3d90,0x3dd0),select=(0x3ed0,0x3ef4),store=(0x3f00,0x3f24),sprite=(0x3dd0,0x3ecc))
PARAMETERS=dict(load=[('state','board_set'),('name','board_name')],save=[('state','board_set'),('name','board_name')],
    select=[('state','board_set'),('index','u32')],store=[('state','board_set'),('index','u32')],sprite=[('kind','u32')])
SERVICES=dict(open=[('state','board_set'),('name','board_name'),('writing','u32')],
    read=[('state','board_set'),('file','board_file'),('bytes','board_bytes')],
    write=[('state','board_set'),('file','board_file'),('bytes','board_bytes')],close=[('state','board_set'),('file','board_file')])
TYPES=[dict(id='unit',kind='void'),dict(id='u32',kind='integer',signed=False,width_bits=32),
    *[dict(id='board_'+name,kind='opaque',nominal_id='dxball.board.'+name) for name in ('set','name','file','bytes')]]
C_TYPES=dict(unit='void',u32='uint32_t',**{'board_'+n:'board_'+n+' *' for n in ('set','name','file','bytes')})
HOOKS=dict(open=(0xe190,0xe1a5),read=(0xe580,0xe590),write=(0xe6c0,0xe6d0),close=(0xdf50,0xdf58))


def bridge_spec():
    return dict(adapters={name:dict(symbol='board_'+name,kind='portable',context=True,outcomes={'return':None})
        for name in SERVICES},transports={},native_symbol=None)


def bridge():
    text='#include "portable-component-implementation.h"\n#include "board-runtime.h"\n#include "comparison-service-bridge.h"\n'
    for index,(name,parameters) in enumerate(PARAMETERS.items()):
        result='uint32_t' if name=='sprite' else 'void';signature=', '.join(C_TYPES[t]+' '+n for n,t in parameters)
        arguments=', '.join(n for n,_ in parameters);prefix='uint32_t result=' if name=='sprite' else ''
        text+=f'''{result} fixture_board_{name}({signature}) {{
    board_enter({index}); spx_board_data_services_v5 services=spx_board_data_bind_services(NULL);
    spx_board_data_context_v5 context={{0}}; context.services=&services;
    spx_board_data_services_begin(); {prefix}lifted_board_{name}(&context,{arguments}); spx_board_data_services_end();
    {"return result;" if prefix else ""}
}}
'''
    return text


def runtime_header():
    text='#ifndef DXBALL_BOARD_RUNTIME_H\n#define DXBALL_BOARD_RUNTIME_H\n#include "board-state.h"\nvoid board_enter(unsigned);\n'
    for name,parameters in PARAMETERS.items():
        text+=('uint32_t' if name=='sprite' else 'void')+' fixture_board_'+name+'('+', '.join(C_TYPES[t] for _,t in parameters)+');\n'
    for name,parameters in SERVICES.items():
        text+=('board_file *' if name=='open' else 'void')+' board_'+name+'(void *'+''.join(', '+C_TYPES[t] for _,t in parameters)+');\n'
    return text+'#endif\n'


def data_header(original):
    image=pefile.PE(str(original));values=[]
    for address in struct.unpack('<23I',image.get_data(0x3e70,92)):
        code=image.get_data(address-0x400000,6)
        if code.startswith(b'\x33\xc0\xc3'):values.append(0)
        elif code[0]==0xb8 and code[5]==0xc3:values.append(struct.unpack('<I',code[1:5])[0])
        else:raise ValueError('unexpected tile mapping body')
    return '/* Values from the pinned native jump table and return instructions. */\nstatic const uint32_t board_sprite_ids[]={'+','.join(str(x) for x in values)+'};\n'


def cases():
    names=['first-board','last-board','middle-board','failed-read-open','failed-write-open','empty-read','one-byte-read',
        'partial-first-board','whole-first-board','partial-last-board','short-write','empty-write','retained-boards','unknown-tile-values']
    return [dict(id=name,arguments=[str(i)]) for i,name in enumerate(names)]


def prepare(original,boards,output):
    started=time.monotonic()
    if sha256_file(original)!=PE_SHA256 or boards.stat().st_size!=20000:raise ValueError('requires pinned DX-Ball and its 20,000-byte board asset')
    output.mkdir(parents=True,exist_ok=False)
    definitions={name:ServiceDefinition.create(identity='dxball.boards.'+name,types=TYPES,parameters=parameters,
        result='board_file' if name=='open' else 'unit',nullable_result=name=='open',resources=[],effects=['dxball.boards.'+name],
        outcomes=['return'],unobserved=['Explicit byte transfer, FILE identity and lifetime boundary in BOUNDARY.md.']) for name,parameters in SERVICES.items()}
    used=dict(load=['open','read','close'],save=['open','write','close'],select=[],store=[],sprite=[])
    interface=component_interface(component_id='board-data',types=TYPES,services=definitions,
        operations={name:OperationDefinition(parameters,'u32' if name=='sprite' else 'unit',used[name]) for name,parameters in PARAMETERS.items()})
    catalog=service_catalog(definitions).to_payload()
    write_json(output/'interface.json',interface.to_payload());write_json(output/'services.json',catalog);write_json(output/'bridge.json',bridge_spec())
    (output/'bridge.c').write_text(bridge());(output/'board-runtime.h').write_text(runtime_header());(output/'board-data.h').write_text(data_header(original))
    sources={'board.c':HERE/'board.c','board-state.h':HERE/'board-state.h','board-data.h':output/'board-data.h'}
    args=['component','start','dxball','board-data','--interface-intent',str(output/'interface.json'),
        '--service-catalog',str(output/'services.json'),'--service-bridge',str(output/'bridge.json'),
        '--assumption-file',str(HERE/'BOUNDARY.md'),'--remove-source','source/component.c','--output',str(output/'authoring')]
    for name in RANGES:args+=['--operation-symbol',name+'=lifted_board_'+name]
    for name,path in sources.items():args+=['--source-file','source/'+name+'='+str(path)]
    ran=subprocess.run([sys.executable,'-m','spaghetti_extractor',*args],capture_output=True,text=True)
    (output/'start.stdout').write_text(ran.stdout);(output/'start.stderr').write_text(ran.stderr)
    if ran.returncode:raise RuntimeError('inspect '+str(output/'start.stderr'))
    entries={**{'board_'+name:span for name,span in RANGES.items()},**{'board_service_'+name:span for name,span in HOOKS.items()},'startup':(0xeaa0,0xeaa5)}
    (output/'native-image.h').write_text('\n'.join(native_entry_header(original=original,expected_sha256=PE_SHA256,module=None,
        entry_rva=lo,end_rva=hi,installer='install_'+name) for name,(lo,hi) in entries.items()))
    environment=native_environment()
    prepare_comparison_package(interface_package=output/'authoring/interface.json',source_files={name:output/'authoring/source'/name for name in sources},
        operation_symbols={name:'lifted_board_'+name for name in RANGES},target_id='dxball',component_id='board-data',
        adapter_files={'runtime.c':HERE/'runtime.c','bridge.c':output/'bridge.c'},
        include_files={'board-runtime.h':output/'board-runtime.h','native-image.h':output/'native-image.h',**native_adapter_headers(),**observation_headers()},
        **{**environment,'runtime_files':{**environment['runtime_files'],'DXBall.exe':original,'default.bds':boards}},
        original_files=['runtime/DXBall.exe'],oracle_kind='native-original',cases=cases(),observation_fields=['boards'],
        assumptions=[(HERE/'BOUNDARY.md').read_text()],scope='Actual board collection I/O, current/saved board copies and complete tile-to-sprite mapping.',
        service_catalog=catalog,service_bridge=bridge_spec(),export_adapters=['adapters/bridge.c'],
        program_driver=dict(kind='pe32-import',image='runtime/DXBall.exe',library='dx-boards.dll',symbol='dx_boards_anchor'),output=output/'board-data')
    write_json(output/'preparation.json',dict(seconds=time.monotonic()-started,cases=len(cases()),original_source_consulted=False,tool_internal_changes=False))


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('original','boards','output'):p.add_argument(name,type=Path)
    a=p.parse_args();prepare(a.original.resolve(),a.boards.resolve(),a.output.resolve())
