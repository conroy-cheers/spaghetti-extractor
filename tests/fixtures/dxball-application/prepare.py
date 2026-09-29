"""Prepare actual WinMain, window dispatch and instance lifetime as portable C."""
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
RANGES=dict(run=(0xd010,0xd12d),event=(0xd130,0xd49a),acquire=(0xd4b0,0xd500),release=(0xd500,0xd51b))
OP_PARAMETERS=dict(run=[('state','shell_state'),('instance','shell_handle'),('show','u32')],
    event=[('state','shell_state'),('window','shell_handle'),('message','u32'),('wparam','u32'),('lparam','u32')],
    acquire=[('state','shell_state')],release=[('state','shell_state')])
OP_RESULTS=dict(run='u32',event='u32',acquire='shell_handle',release='unit')
HOOKS=dict(windowed_graphics=0xcc60,fullscreen_graphics=0xc810,initialize_clock=0xdba0,initialize_trig=0xd6b0,
    frame=0xab10,shutdown=0xae50,stop_sounds=0x3460,stop_music=0x2200,clear_sprites=0xbcc0,
    focus_sounds=0x2c80,resume_music=0x21a0,suspend_sounds=0x2f20,pause_music=0x21d0,
    leave_scene=0xaca0,key=0xabf0,terminate=0xe3d0)
IMPORTS=dict(open_semaphore=('KERNEL32.dll','OpenSemaphoreA'),create_semaphore=('KERNEL32.dll','CreateSemaphoreA'),
    close_handle=('KERNEL32.dll','CloseHandle'),message_box=('USER32.dll','MessageBoxA'),
    cursor_position=('USER32.dll','GetCursorPos'),peek_message=('USER32.dll','PeekMessageA'),
    get_message=('USER32.dll','GetMessageA'),translate_message=('USER32.dll','TranslateMessage'),
    dispatch_message=('USER32.dll','DispatchMessageA'),wait_message=('USER32.dll','WaitMessage'),
    post_quit=('USER32.dll','PostQuitMessage'),set_cursor=('USER32.dll','SetCursor'),
    post_message=('USER32.dll','PostMessageA'),capture=('USER32.dll','SetCapture'),
    release_capture=('USER32.dll','ReleaseCapture'),default_event=('USER32.dll','DefWindowProcA'))
ARGS={n:[] for n in [*HOOKS,*IMPORTS,'release_surface','release_palette','palette_entries']}
ARGS.update(windowed_graphics=[('instance','shell_handle'),('show','u32')],
    fullscreen_graphics=[('instance','shell_handle'),('show','u32')],shutdown=[('reason','u32')],
    focus_sounds=[('window','shell_handle')],leave_scene=[('reason','u32')],key=[('key','u32')],terminate=[('code','u32')],
    open_semaphore=[('access','u32'),('inherit','u32'),('name','asset_name')],
    create_semaphore=[('inherit','u32'),('initial','u32'),('maximum','u32'),('name','asset_name')],
    close_handle=[('handle','shell_handle')],message_box=[('window','shell_handle'),('text','asset_name'),('caption','asset_name'),('flags','u32')],
    cursor_position=[('point','shell_point')],post_quit=[('code','u32')],set_cursor=[('cursor','shell_handle')],
    post_message=[('window','shell_handle'),('message','u32'),('wparam','u32'),('lparam','u32')],capture=[('window','shell_handle')],
    default_event=[('window','shell_handle'),('message','u32'),('wparam','u32'),('lparam','u32')],
    release_surface=[('surface','cleanup_surface')],release_palette=[('palette','shell_palette')],
    palette_entries=[('palette','shell_palette'),('colors','pcx_state')])
for n in ('peek_message','get_message','translate_message','dispatch_message'):ARGS[n]=[('message','shell_message')]
PARAMETERS={n:[('state','shell_state'),*args] for n,args in ARGS.items()}
RESULTS={n:'shell_handle' if n in ('open_semaphore','create_semaphore') else 'u32' if n in (
    'windowed_graphics','fullscreen_graphics','peek_message','get_message','default_event') else 'unit' for n in PARAMETERS}
TYPES=[dict(id='unit',kind='void'),dict(id='u32',kind='integer',width_bits=32,signed=False),
    *[dict(id=n,kind='opaque',nominal_id=nominal) for n,nominal in [('shell_state','dxball.application.state'),
        ('shell_handle','dxball.application.handle'),('shell_point','dxball.application.point'),
        ('shell_message','dxball.application.message'),('shell_palette','dxball.application.palette'),
        ('cleanup_surface','dxball.cleanup.surface'),('pcx_state','dxball.pcx.state'),('asset_name','dxball.asset.name')]]]
C_TYPES=dict(unit='void',u32='uint32_t',**{n:n+' *' for n in ('shell_state','shell_handle','shell_point','shell_message','shell_palette','pcx_state','asset_name')},cleanup_surface='font_surface *')
CASE_NAMES=['guard-created','guard-existing','guard-create-failed','guard-close-callback','guard-close-absent',
    'event-defaults','activation-and-keys','escape-menu','escape-game','mouse-buttons','mouse-callback',
    'focus-state','power-state','power-broadcast','palette-guards','destroy-populated','destroy-no-graphics',
    'destroy-callbacks','cursor-failure','run-windowed','run-fullscreen','graphics-failure','instance-failure',
    'inactive-wait','setup-callback','translated-message','get-message-error','quit-result']

def bridge_spec():
    return dict(adapters={n:dict(symbol='shell_'+n,kind='portable',context=True,outcomes={'return':None}) for n in PARAMETERS},transports={},native_symbol=None)

def bridge():
    text='#include "portable-component-implementation.h"\n#include "shell-runtime.h"\n#include "comparison-service-bridge.h"\n'
    for i,n in enumerate(RANGES):
        result=C_TYPES[OP_RESULTS[n]];params=','.join(C_TYPES[t]+' '+p for p,t in OP_PARAMETERS[n]);args=','.join(p for p,_ in OP_PARAMETERS[n])
        text+=f'{result} fixture_shell_{n}({params}) {{\n    shell_enter({i});spx_application_shell_services_v5 services=spx_application_shell_bind_services(NULL);\n    spx_application_shell_context_v5 context={{0}};context.services=&services;spx_application_shell_services_begin();\n'
        text+=('    '+result+' result=' if result!='void' else '    ')+f'lifted_shell_{n}(&context,{args});spx_application_shell_services_end();'+('return result;' if result!='void' else '')+'\n}\n'
    return text

def runtime_header():
    text='#ifndef DXBALL_SHELL_RUNTIME_H\n#define DXBALL_SHELL_RUNTIME_H\n#include "shell-state.h"\nvoid shell_enter(unsigned);\n'
    for n in RANGES:text+=C_TYPES[OP_RESULTS[n]]+' fixture_shell_'+n+'('+','.join(C_TYPES[t] for _,t in OP_PARAMETERS[n])+');\n'
    for n,params in PARAMETERS.items():text+=C_TYPES[RESULTS[n]]+' shell_'+n+'(void *'+''.join(', '+C_TYPES[t] for _,t in params)+');\n'
    return text+'enum { '+', '.join('SHELL_SERVICE_'+n.upper()+'='+str(i) for i,n in enumerate(PARAMETERS))+' };\n#endif\n'

def prepare(original,shared,output):
    started=time.monotonic();output.mkdir(parents=True,exist_ok=False)
    if sha256_file(original)!=PE_SHA256:raise ValueError('requires pinned DX-Ball PE32')
    services={n:ServiceDefinition.create(identity='dxball.application.'+n,types=TYPES,parameters=params,result=RESULTS[n],
        resources=[],effects=['dxball.application.'+n],outcomes=['return'],nonlocal_outcomes=['process-exit'] if n=='terminate' else [],
        unobserved=['Shared objects, platform state and callback contract in BOUNDARY.md; practical comparisons, not checked heap summaries.']) for n,params in PARAMETERS.items()}
    interface=component_interface(component_id='application-shell',types=TYPES,services=services,
        operations={n:OperationDefinition(OP_PARAMETERS[n],OP_RESULTS[n],list(PARAMETERS)) for n in RANGES})
    catalog=service_catalog(services).to_payload()
    write_json(output/'interface.json',interface.to_payload());write_json(output/'services.json',catalog);write_json(output/'bridge.json',bridge_spec())
    (output/'bridge.c').write_text(bridge());(output/'shell-runtime.h').write_text(runtime_header())
    sources={'shell.c':HERE/'shell.c','shell-state.h':HERE/'shell-state.h'};pending=['scene-state.h']
    while pending:
        n=pending.pop()
        if n in sources:continue
        p=shared/'source'/n
        if not p.is_file():raise ValueError('missing shared header '+n)
        sources[n]=p;pending+=re.findall(r'^#include "([^"]+)"',p.read_text(),re.MULTILINE)
    args=['component','start','dxball','application-shell','--interface-intent',str(output/'interface.json'),
        '--service-catalog',str(output/'services.json'),'--service-bridge',str(output/'bridge.json'),
        '--assumption-file',str(HERE/'BOUNDARY.md'),'--remove-source','source/component.c','--output',str(output/'authoring')]
    for n in RANGES:args+=['--operation-symbol',n+'=lifted_shell_'+n]
    for n,p in sources.items():args+=['--source-file','source/'+n+'='+str(p)]
    ran=subprocess.run([sys.executable,'-m','spaghetti_extractor',*args],capture_output=True,text=True)
    (output/'start.stdout').write_text(ran.stdout);(output/'start.stderr').write_text(ran.stderr)
    if ran.returncode:raise ValueError('inspect start.stderr')
    entries={**{'shell_'+n:r for n,r in RANGES.items()},'startup':(0xeaa0,0xeaa5),**{'shell_service_'+n:(r,r+8) for n,r in HOOKS.items()}}
    (output/'native-image.h').write_text('\n'.join(native_entry_header(original=original,expected_sha256=PE_SHA256,module=None,
        entry_rva=lo,end_rva=hi,installer='install_'+n) for n,(lo,hi) in entries.items()))
    imports='\n'.join(f'    HOOK({n},"{dll}","{symbol}")' for n,(dll,symbol) in IMPORTS.items())
    (output/'shell-imports.h').write_text(imports+'\n')
    environment=native_environment()
    prepare_comparison_package(interface_package=output/'authoring/interface.json',source_files={n:output/'authoring/source'/n for n in sources},
        operation_symbols={n:'lifted_shell_'+n for n in RANGES},target_id='dxball',component_id='application-shell',
        adapter_files={'runtime.c':HERE/'runtime.c','bridge.c':output/'bridge.c'},
        include_files={'native-image.h':output/'native-image.h','shell-runtime.h':output/'shell-runtime.h','shell-imports.h':output/'shell-imports.h',
            'shell-native.h':HERE/'shell-native.h',**native_adapter_headers('pe32-entry-hook.h','pe32-import-hook.h'),**observation_headers()},
        **{**environment,'runtime_files':{**environment['runtime_files'],'DXBall.exe':original}},original_files=['runtime/DXBall.exe'],oracle_kind='native-original',
        cases=[dict(id=n,arguments=[str(i)]) for i,n in enumerate(CASE_NAMES)],observation_fields=['application'],
        assumptions=[(HERE/'BOUNDARY.md').read_text()],scope='Actual WinMain, window procedure and instance semaphore lifecycle with explicit message schedules, shared state, callbacks and controlled platform calls.',
        service_catalog=catalog,service_bridge=bridge_spec(),export_adapters=['adapters/bridge.c'],
        program_driver=dict(kind='pe32-import',image='runtime/DXBall.exe',library='dx-shell.dll',symbol='dx_shell_anchor'),output=output/'application-shell')
    write_json(output/'preparation.json',dict(seconds=time.monotonic()-started,cases=len(CASE_NAMES),original_source_consulted=False,tool_internal_changes=False))

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for n in ('original','shared','output'):p.add_argument(n,type=Path)
    a=p.parse_args();prepare(a.original.resolve(),a.shared.resolve(),a.output.resolve())
