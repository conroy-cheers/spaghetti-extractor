"""Author the binary-derived file reader over the shared Win32 file environment."""
import argparse
from pathlib import Path
import subprocess
import sys
import time
from spaghetti_extractor.components.comparison_environment import native_environment,native_adapter_headers
from spaghetti_extractor.components.comparison_original import native_entry_header
from spaghetti_extractor.components.comparison_package import prepare_comparison_package
from spaghetti_extractor.components.comparison_wine_environment import wine_test_backend
from spaghetti_extractor.components.service_authoring import OperationDefinition,ServiceDefinition,component_interface,service_catalog
from spaghetti_extractor.util import sha256_file,write_json

HERE=Path(__file__).resolve().parent
PE_SHA256='191c113582e1f31016a158d40372fa21ea68d9348bf847bbfbc8e7c7bdfe195f'
RANGES=dict(read=(0xd9f0,0xdb13))
OP_PARAMETERS=[('name','reader_name'),('supplied','reader_bytes'),('allocate','u32')]
PARAMETERS=dict(open=[('name','reader_name'),('access','u32'),('share','u32'),('disposition','u32'),('attributes','u32')],
    size=[('file','reader_handle')],allocate=[('size','u32')],read=[('file','reader_handle'),('buffer','reader_bytes'),('size','u32')],
    free=[('buffer','reader_bytes')],close=[('file','reader_handle')])
RESULTS=dict(open='reader_handle',size='u32',allocate='reader_bytes',read='u32',free='unit',close='unit')
TYPES=[dict(id='unit',kind='void'),dict(id='u32',kind='integer',width_bits=32,signed=False),
    *[dict(id=n,kind='opaque',nominal_id='dxball.file.'+n.removeprefix('reader_')) for n in ('reader_name','reader_bytes','reader_handle')]]
C_TYPES=dict(unit='void',u32='uint32_t',reader_name='reader_name *',reader_bytes='reader_bytes *',reader_handle='reader_handle *')
NAMES=['allocated','supplied','fallback','missing','allocation-failure','read-failure','supplied-read-failure',
    'short-read','supplied-short-read','close-failure','size-failure','empty','empty-null-supplied','nonboolean-allocation',
    'positive-read-result','partial-failed-read','fallback-allocation-failure','fallback-read-failure','long-fallback-name',
    'multiple-calls','open-denied','read-zero-success']
CASES=[dict(id=n,arguments=[str(i)]) for i,n in enumerate(NAMES)]

def bridge_spec():
    return dict(adapters={n:dict(symbol='reader_'+n,kind='portable',context=True,outcomes={'return':None}) for n in PARAMETERS},transports={},native_symbol=None)

def runtime_header():
    text='#ifndef DXBALL_READER_RUNTIME_H\n#define DXBALL_READER_RUNTIME_H\n#include "reader-state.h"\nvoid reader_enter(void);\nreader_bytes *fixture_file_read(reader_name *,reader_bytes *,uint32_t);\n'
    for n,p in PARAMETERS.items():text+=C_TYPES[RESULTS[n]]+' reader_'+n+'(void *'+''.join(', '+C_TYPES[t] for _,t in p)+');\n'
    return text+'#endif\n'

def bridge():
    return '''#include "portable-component-implementation.h"
#include "reader-runtime.h"
#include "comparison-service-bridge.h"
reader_bytes *fixture_file_read(reader_name *name,reader_bytes *supplied,uint32_t allocate) {
    reader_enter();spx_file_reader_services_v5 services=spx_file_reader_bind_services(NULL);
    spx_file_reader_context_v5 context={0};context.services=&services;spx_file_reader_services_begin();
    reader_bytes *result=lifted_file_read(&context,name,supplied,allocate);spx_file_reader_services_end();return result;
}
'''

def prepare(original,environment_package,output):
    started=time.monotonic();output.mkdir(parents=True,exist_ok=False)
    if sha256_file(original)!=PE_SHA256:raise ValueError('requires pinned DX-Ball image')
    services={n:ServiceDefinition.create(identity='dxball.file.'+n,types=TYPES,parameters=p,result=RESULTS[n],resources=[],
        effects=['dxball.file.'+n],outcomes=['return'],unobserved=['Input extents and runtime ownership are explicit in BOUNDARY.md.']) for n,p in PARAMETERS.items()}
    interface=component_interface(component_id='file-reader',types=TYPES,services=services,operations={'read':OperationDefinition(OP_PARAMETERS,'reader_bytes',list(PARAMETERS))})
    catalog=service_catalog(services).to_payload();write_json(output/'interface.json',interface.to_payload());write_json(output/'services.json',catalog);write_json(output/'bridge.json',bridge_spec())
    (output/'bridge.c').write_text(bridge());(output/'reader-runtime.h').write_text(runtime_header())
    args=['component','start','dxball','file-reader','--interface-intent',str(output/'interface.json'),'--service-catalog',str(output/'services.json'),
        '--service-bridge',str(output/'bridge.json'),'--assumption-file',str(HERE/'BOUNDARY.md'),'--remove-source','source/component.c',
        '--operation-symbol','read=lifted_file_read','--output',str(output/'authoring')]
    for n in ('reader.c','reader-state.h'):args+=['--source-file','source/'+n+'='+str(HERE/n)]
    ran=subprocess.run([sys.executable,'-m','spaghetti_extractor',*args],capture_output=True,text=True)
    (output/'start.stdout').write_text(ran.stdout);(output/'start.stderr').write_text(ran.stderr)
    if ran.returncode:raise ValueError('inspect start.stderr')
    entries=dict(startup=(0xeaa0,0xeaa8),file_read=RANGES['read'],reader_allocate=(0xe2f0,0xe2f8),reader_free=(0xe2a0,0xe2a8))
    (output/'native-image.h').write_text('\n'.join(native_entry_header(original=original,expected_sha256=PE_SHA256,module=None,entry_rva=lo,end_rva=hi,
        installer='install_'+n) for n,(lo,hi) in entries.items()))
    backend=wine_test_backend();environment=native_environment(environment_package)
    prepare_comparison_package(interface_package=output/'authoring/interface.json',source_files={n:output/'authoring/source'/n for n in ('reader.c','reader-state.h')},
        operation_symbols={'read':'lifted_file_read'},target_id='dxball',component_id='file-reader',
        adapter_files={**backend['adapter_files'],'runtime.c':HERE/'runtime.c','bridge.c':output/'bridge.c'},
        include_files={**backend['include_files'],**native_adapter_headers('pe32-entry-hook.h'),'native-image.h':output/'native-image.h','reader-runtime.h':output/'reader-runtime.h'},
        **{**environment,'runtime_files':{**environment['runtime_files'],'DXBall.exe':original}},original_files=['runtime/DXBall.exe'],oracle_kind='native-original',
        cases=CASES,observation_fields=['reader'],assumptions=[(HERE/'BOUNDARY.md').read_text()],
        scope='File reader with actual machine fallback and ownership policy, shared Win32 file effects, and initialized byte/lifetime inputs; no game startup.',
        service_catalog=catalog,service_bridge=bridge_spec(),export_adapters=['adapters/bridge.c'],
        program_driver=dict(kind='pe32-import',image='runtime/DXBall.exe',library='dx-reader.dll',symbol='dx_reader_anchor'),output=output/'file-reader')
    write_json(output/'preparation.json',dict(seconds=time.monotonic()-started,cases=len(CASES),original_source_consulted=False))

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for n in ('original','environment_package','output'):p.add_argument(n,type=Path)
    a=p.parse_args();prepare(a.original.resolve(),a.environment_package.resolve(),a.output.resolve())
