"""Prepare the MDS event expander from the pinned machine entry and retained assets."""
import argparse
from pathlib import Path
import subprocess
import sys
import time

from spaghetti_extractor.components.comparison_environment import native_adapter_headers,native_environment,observation_headers
from spaghetti_extractor.components.comparison_original import native_entry_header
from spaghetti_extractor.components.comparison_package import prepare_comparison_package
from spaghetti_extractor.components.service_authoring import OperationDefinition,component_interface
from spaghetti_extractor.util import sha256_file,write_json

HERE=Path(__file__).resolve().parent
PE_SHA256='191c113582e1f31016a158d40372fa21ea68d9348bf847bbfbc8e7c7bdfe195f'
ASSETS=['12flight.mds','Acker-gs.mds','Brain.mds','Ethno_pa.mds','Freebee.mds','Gmfigaro.mds']
NAMES=['empty','one-short','two-short','long-four','long-three-padded','mixed-events',
    'length-one','length-two','length-three','delta-only','no-output-space','eleven-output-bytes',
    'exact-output-space','extra-output-space','short-long-payload','short-long-destination',
    'trailing-delta','short-with-low-bits','empty-long','huge-long','unaligned-input','unaligned-output',
    'historical-failed-size','empty-zero-capacity','ignored-input-capacity','success-then-failure',
    'generated-short-events','generated-mixed-events']
CASES=[dict(id=n,arguments=[str(i)]) for i,n in enumerate(NAMES)]+[
    dict(id='asset-'+p,arguments=[str(100+i)]) for i,p in enumerate(ASSETS)]

def bridge():
    return '''#include "portable-component-implementation.h"
#include "mds-events-runtime.h"
uint32_t fixture_mds_expand(mds_event_block *input,mds_event_block *output) {
    mds_events_enter();spx_mds_events_context_v5 context={0};
    return lifted_mds_expand(&context,input,output);
}
'''

def runtime_header():
    return '''#ifndef DXBALL_MDS_EVENTS_RUNTIME_H
#define DXBALL_MDS_EVENTS_RUNTIME_H
#include "mds-events-state.h"
void mds_events_enter(void);
uint32_t fixture_mds_expand(mds_event_block *,mds_event_block *);
#endif
'''

def prepare(original,environment_package,output):
    started=time.monotonic();output.mkdir(parents=True,exist_ok=False)
    if sha256_file(original)!=PE_SHA256:raise ValueError('requires pinned DX-Ball image')
    interface=component_interface(component_id='mds-events',services={},types=[
        dict(id='u32',kind='integer',width_bits=32,signed=False),
        dict(id='mds_event_block',kind='opaque',nominal_id='dxball.mds.event-block')],
        operations={'expand':OperationDefinition([('input','mds_event_block'),('output','mds_event_block')],'u32')})
    write_json(output/'interface.json',interface.to_payload())
    (output/'bridge.c').write_text(bridge());(output/'mds-events-runtime.h').write_text(runtime_header())
    args=['component','start','dxball','mds-events','--interface-intent',str(output/'interface.json'),
        '--assumption-file',str(HERE/'BOUNDARY.md'),'--remove-source','source/component.c',
        '--operation-symbol','expand=lifted_mds_expand','--output',str(output/'authoring')]
    for name in ('events.c','mds-events-state.h'):args+=['--source-file','source/'+name+'='+str(HERE/name)]
    ran=subprocess.run([sys.executable,'-m','spaghetti_extractor',*args],capture_output=True,text=True)
    (output/'start.stdout').write_text(ran.stdout);(output/'start.stderr').write_text(ran.stderr)
    if ran.returncode:raise ValueError('inspect start.stderr')
    (output/'native-image.h').write_text('\n'.join(native_entry_header(original=original,expected_sha256=PE_SHA256,
        module=None,entry_rva=lo,end_rva=hi,installer='install_'+name) for name,(lo,hi) in
        dict(startup=(0xeaa0,0xeaa8),mds_expand=(0x1d60,0x1e33)).items()))
    environment=native_environment(environment_package)
    assets={name:environment_package/'runtime'/name for name in ASSETS}
    prepare_comparison_package(interface_package=output/'authoring/interface.json',
        source_files={name:output/'authoring/source'/name for name in ('events.c','mds-events-state.h')},
        operation_symbols={'expand':'lifted_mds_expand'},target_id='dxball',component_id='mds-events',
        adapter_files={'runtime.c':HERE/'runtime.c','bridge.c':output/'bridge.c'},
        include_files={**observation_headers(),**native_adapter_headers('pe32-entry-hook.h'),
            'native-image.h':output/'native-image.h','mds-events-runtime.h':output/'mds-events-runtime.h'},
        **{**environment,'runtime_files':{**environment['runtime_files'],**assets,'DXBall.exe':original}},
        original_files=['runtime/DXBall.exe'],oracle_kind='native-original',cases=CASES,observation_fields=['mds_events'],
        assumptions=[(HERE/'BOUNDARY.md').read_text()],
        scope='MDS event expansion including partial failures, untouched byte history and all bundled music blocks; no game startup.',
        export_adapters=['adapters/bridge.c'],
        program_driver=dict(kind='pe32-import',image='runtime/DXBall.exe',library='dx-mds-events.dll',symbol='dx_mds_events_anchor'),
        output=output/'mds-events')
    write_json(output/'preparation.json',dict(seconds=time.monotonic()-started,cases=len(CASES),
        assets={name:sha256_file(path) for name,path in assets.items()},original_source_consulted=False,tool_internal_changes=False))

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('original','environment_package','output'):p.add_argument(name,type=Path)
    a=p.parse_args();prepare(a.original.resolve(),a.environment_package.resolve(),a.output.resolve())
