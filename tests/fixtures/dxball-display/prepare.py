"""Prepare complete native windowed/fullscreen display setup as ordinary C."""
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
RANGES=dict(windowed=(0xcc60,0xd006),fullscreen=(0xc810,0xcc52))
OP_PARAMETERS=[('state','display_state'),('instance','shell_handle'),('show','u32'),('history','display_history')]
IMPORTS=dict(load_icon=('USER32.dll','LoadIconA'),load_cursor=('USER32.dll','LoadCursorA'),stock_object=('GDI32.dll','GetStockObject'),
    register_class=('USER32.dll','RegisterClassA'),create_window=('USER32.dll','CreateWindowExA'),show_window=('USER32.dll','ShowWindow'),
    update_window=('USER32.dll','UpdateWindow'),focus_window=('USER32.dll','SetFocus'),destroy_window=('USER32.dll','DestroyWindow'),
    message=('USER32.dll','MessageBoxA'))
ARGS=dict(load_icon=[('instance','shell_handle'),('resource','u32')],load_cursor=[('instance','shell_handle'),('resource','u32')],
    stock_object=[('object','u32')],register_class=[('window_class','display_class')],
    create_window=[('instance','shell_handle'),('name','asset_name'),('style','u32'),('width','u32'),('height','u32')],
    show_window=[('window','shell_handle'),('command','u32')],update_window=[('window','shell_handle')],focus_window=[('window','shell_handle')],
    initialize_sound=[('window','shell_handle')],create_draw=[],cooperative=[('device','shell_device'),('window','shell_handle'),('flags','u32')],
    display_mode=[('device','shell_device'),('width','u32'),('height','u32'),('depth','u32')],
    capabilities=[('device','shell_device'),('caps','display_caps')],create_surface=[('device','shell_device'),('descriptor','display_surface'),('slot','u32')],
    attached_surface=[('surface','cleanup_surface'),('caps','u32')],create_clipper=[('device','shell_device')],
    clipper_window=[('clipper','display_clipper'),('window','shell_handle'),('flags','u32')],
    attach_clipper=[('surface','cleanup_surface'),('clipper','display_clipper')],
    destroy_window=[('window','shell_handle')],message=[('window','shell_handle'),('text','asset_name'),('caption','asset_name'),('flags','u32')])
PARAMETERS={n:[('state','display_state'),*args] for n,args in ARGS.items()}
HANDLE_RESULTS={'load_icon','load_cursor','stock_object','create_window'}
VOID_RESULTS={'register_class','show_window','update_window','focus_window','initialize_sound','capabilities','destroy_window','message'}
RESULTS={n:'shell_handle' if n in HANDLE_RESULTS else 'unit' if n in VOID_RESULTS else 'u32' for n in PARAMETERS}
NOMINALS={n:'dxball.display.'+n.removeprefix('display_') for n in ['display_state','display_history','display_class','display_caps','display_surface','display_clipper']}
NOMINALS.update(shell_handle='dxball.application.handle',shell_device='dxball.application.device',cleanup_surface='dxball.cleanup.surface',asset_name='dxball.asset.name')
TYPES=[dict(id='unit',kind='void'),dict(id='u32',kind='integer',width_bits=32,signed=False),*[dict(id=n,kind='opaque',nominal_id=v) for n,v in NOMINALS.items()]]
C_TYPES=dict(unit='void',u32='uint32_t',**{n:n+' *' for n in NOMINALS});C_TYPES['cleanup_surface']='font_surface *'
CASE_NAMES=['success','create-window-fails','draw-fails','draw-positive-status','cooperative-fails','display-mode-fails',
    'primary-fails','primary-positive-status','attached-fails','back-fails','clipper-fails','clipper-window-fails',
    'attach-primary-fails','attach-flip-fails','no-clipper','nonboolean-clipper','capability-bit','low-video-memory',
    'caps-unwritten','caps-partial','window-callbacks','error-window-callbacks','primary-callback','caps-callback','descriptor-callback',
    'caps-zero-on-error','class-resource-failures']
CASES=[dict(id=('fullscreen-' if mode else 'windowed-')+CASE_NAMES[case],arguments=[str(mode),str(case)])
    for mode,indices in [(0,[0,1,2,3,4,6,7,9,10,11,12,14,15,16,18,20,21,22,24,26]),
        (1,[0,1,2,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26])] for case in indices]

def bridge_spec():
    return dict(adapters={n:dict(symbol='display_'+n,kind='portable',context=True,outcomes={'return':None}) for n in PARAMETERS},transports={},native_symbol=None)

def bridge():
    text='#include "portable-component-implementation.h"\n#include "display-runtime.h"\n#include "comparison-service-bridge.h"\n'
    for i,n in enumerate(RANGES):
        text+='uint32_t fixture_display_'+n+'('+','.join(C_TYPES[t]+' '+p for p,t in OP_PARAMETERS)+') {\n'
        text+=f'    display_enter({i});spx_display_setup_services_v5 services=spx_display_setup_bind_services(NULL);\n    spx_display_setup_context_v5 context={{0}};context.services=&services;spx_display_setup_services_begin();\n'
        text+=f'    uint32_t result=lifted_display_{n}(&context,state,instance,show,history);spx_display_setup_services_end();return result;\n}}\n'
    return text

def runtime_header():
    text='#ifndef DXBALL_DISPLAY_RUNTIME_H\n#define DXBALL_DISPLAY_RUNTIME_H\n#include "display-state.h"\nvoid display_enter(unsigned);\n'
    for n in RANGES:text+='uint32_t fixture_display_'+n+'('+','.join(C_TYPES[t] for _,t in OP_PARAMETERS)+');\n'
    for n,params in PARAMETERS.items():text+=C_TYPES[RESULTS[n]]+' display_'+n+'(void *'+''.join(', '+C_TYPES[t] for _,t in params)+');\n'
    return text+'enum { '+', '.join('DISPLAY_SERVICE_'+n.upper()+'='+str(i) for i,n in enumerate(PARAMETERS))+' };\n#endif\n'

def prepare(original,shared,output):
    started=time.monotonic();output.mkdir(parents=True,exist_ok=False)
    if sha256_file(original)!=PE_SHA256:raise ValueError('requires pinned DX-Ball PE32')
    services={n:ServiceDefinition.create(identity='dxball.display.'+n,types=TYPES,parameters=params,result=RESULTS[n],
        resources=[],effects=['dxball.display.'+n],outcomes=['return'],
        unobserved=['Shared state, capability history, descriptor fields and synchronous callbacks in BOUNDARY.md; practical comparisons, not checked heap summaries.']) for n,params in PARAMETERS.items()}
    interface=component_interface(component_id='display-setup',types=TYPES,services=services,
        operations={n:OperationDefinition(OP_PARAMETERS,'u32',list(PARAMETERS)) for n in RANGES})
    catalog=service_catalog(services).to_payload()
    write_json(output/'interface.json',interface.to_payload());write_json(output/'services.json',catalog);write_json(output/'bridge.json',bridge_spec())
    (output/'bridge.c').write_text(bridge());(output/'display-runtime.h').write_text(runtime_header())
    sources={'display.c':HERE/'display.c','display-state.h':HERE/'display-state.h'};pending=['shell-state.h','damage-state.h']
    while pending:
        n=pending.pop()
        if n in sources:continue
        candidates=[shared/'source'/n,*sorted((shared/'dependencies').glob('*/source/'+n))]
        p=next((p for p in candidates if p.is_file()),None)
        if p is None:raise ValueError('missing shared header '+n)
        sources[n]=p;pending+=re.findall(r'^#include "([^"]+)"',p.read_text(),re.MULTILINE)
    args=['component','start','dxball','display-setup','--interface-intent',str(output/'interface.json'),
        '--service-catalog',str(output/'services.json'),'--service-bridge',str(output/'bridge.json'),
        '--assumption-file',str(HERE/'BOUNDARY.md'),'--remove-source','source/component.c','--output',str(output/'authoring')]
    for n in RANGES:args+=['--operation-symbol',n+'=lifted_display_'+n]
    for n,p in sources.items():args+=['--source-file','source/'+n+'='+str(p)]
    ran=subprocess.run([sys.executable,'-m','spaghetti_extractor',*args],capture_output=True,text=True)
    (output/'start.stdout').write_text(ran.stdout);(output/'start.stderr').write_text(ran.stderr)
    if ran.returncode:raise ValueError('inspect start.stderr')
    entries={**{'display_'+n:r for n,r in RANGES.items()},'startup':(0xeaa0,0xeaa5),
        'display_sound':(0x2c60,0x2c80),'display_draw':(0xdbe0,0xdbe6),'display_reset':(0xbc90,0xbcbb),'display_bind':(0xbd60,0xbd6a)}
    (output/'native-image.h').write_text('\n'.join(native_entry_header(original=original,expected_sha256=PE_SHA256,module=None,
        entry_rva=lo,end_rva=hi,installer='install_'+n) for n,(lo,hi) in entries.items()))
    (output/'display-imports.h').write_text('\n'.join(f'HOOK({n},"{dll}","{symbol}")' for n,(dll,symbol) in IMPORTS.items())+'\n')
    environment=native_environment()
    prepare_comparison_package(interface_package=output/'authoring/interface.json',source_files={n:output/'authoring/source'/n for n in sources},
        operation_symbols={n:'lifted_display_'+n for n in RANGES},target_id='dxball',component_id='display-setup',
        adapter_files={'runtime.c':HERE/'runtime.c','bridge.c':output/'bridge.c'},
        include_files={'native-image.h':output/'native-image.h','display-runtime.h':output/'display-runtime.h',
            'display-imports.h':output/'display-imports.h','display-native.h':HERE/'display-native.h',
            'shell-native.h':HERE.parent/'dxball-application/shell-native.h',
            **native_adapter_headers('pe32-entry-hook.h','pe32-import-hook.h'),**observation_headers()},
        **{**environment,'runtime_files':{**environment['runtime_files'],'DXBall.exe':original}},original_files=['runtime/DXBall.exe'],oracle_kind='native-original',
        cases=CASES,observation_fields=['display'],assumptions=[(HERE/'BOUNDARY.md').read_text()],
        scope='Complete windowed/fullscreen initialization, shared resources, capability history, callbacks and private table reset/bind helpers; controlled platform services without normal game startup.',
        service_catalog=catalog,service_bridge=bridge_spec(),export_adapters=['adapters/bridge.c'],
        program_driver=dict(kind='pe32-import',image='runtime/DXBall.exe',library='dx-display.dll',symbol='dx_display_anchor'),output=output/'display-setup')
    write_json(output/'preparation.json',dict(seconds=time.monotonic()-started,cases=len(CASES),original_source_consulted=False,tool_internal_changes=False))

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for n in ('original','shared','output'):p.add_argument(n,type=Path)
    a=p.parse_args();prepare(a.original.resolve(),a.shared.resolve(),a.output.resolve())
