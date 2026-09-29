"""Prepare native numeric bodies using the public component workflow."""
import argparse
from pathlib import Path
import subprocess
import sys
import time
from spaghetti_extractor.components.comparison_environment import native_environment,native_adapter_headers,observation_headers
from spaghetti_extractor.components.comparison_package import prepare_comparison_package
from spaghetti_extractor.components.service_authoring import OperationDefinition,component_interface
from spaghetti_extractor.util import sha256_file,write_json

HERE=Path(__file__).resolve().parent
PE_SHA256='191c113582e1f31016a158d40372fa21ea68d9348bf847bbfbc8e7c7bdfe195f'
RANGES=dict(initialize=(0xd6b0,0xd703),sine=(0xd710,0xd740),cosine=(0xd740,0xd770),sine_value=(0xd770,0xd7ac),
    cosine_value=(0xd7b0,0xd7ec),project_x=(0xd7f0,0xd817),project_y=(0xd820,0xd847),pan=(0x3550,0x356b))
OPS={n:([('tables','math_tables')]+([] if n=='initialize' else [('origin','u32'),('angle','u32'),('distance','u32')] if n.startswith('project') else [('angle','u32')])) for n in RANGES}
OPS['pan']=[('position','u32')]
RESULTS={n:'unit' if n=='initialize' else 'f64' if n.endswith('_value') else 'u32' for n in RANGES}
TYPES=[dict(id='unit',kind='void'),dict(id='u32',kind='integer',width_bits=32,signed=False),
    dict(id='f64',kind='float',format='binary64',value_bits=64),dict(id='math_tables',kind='opaque',nominal_id='dxball.math.tables')]
C_TYPES=dict(unit='void',u32='uint32_t',f64='double',math_tables='math_tables *')
NAMES=['initialize','initialize-again','reader-extremes','reader-sweep','pan-extremes','pan-sweep','pan-generated','initialized-projections','pattern-projections']
CASES=[dict(id=n,arguments=[str(i)]) for i,n in enumerate(NAMES)]

def bridge():
    text='#include "portable-component-implementation.h"\n#include "math-runtime.h"\n'
    for i,(n,p) in enumerate(OPS.items()):
        text+=C_TYPES[RESULTS[n]]+' fixture_math_'+n+'('+','.join(C_TYPES[t]+' '+a for a,t in p)+') {\n'
        text+=f'    math_enter({i});spx_math_support_context_v5 context={{0}};\n    '
        text+=('return ' if RESULTS[n]!='unit' else '')+'lifted_math_'+n+'(&context'+''.join(','+a for a,_ in p)+');\n}\n'
    return text

def runtime_header():
    text='#ifndef DXBALL_MATH_RUNTIME_H\n#define DXBALL_MATH_RUNTIME_H\n#include "math-state.h"\nvoid math_enter(unsigned);\n'
    for n,p in OPS.items():text+=C_TYPES[RESULTS[n]]+' fixture_math_'+n+'('+','.join(C_TYPES[t] for _,t in p)+');\n'
    return text+'#endif\n'

def prepare(original,environment_package,output):
    from spaghetti_extractor.components.comparison_original import native_entry_header
    started=time.monotonic();output.mkdir(parents=True,exist_ok=False)
    if sha256_file(original)!=PE_SHA256:raise ValueError('requires pinned DX-Ball image')
    interface=component_interface(component_id='math-support',types=TYPES,services={},
        operations={n:OperationDefinition(p,RESULTS[n],[]) for n,p in OPS.items()})
    write_json(output/'interface.json',interface.to_payload());(output/'bridge.c').write_text(bridge());(output/'math-runtime.h').write_text(runtime_header())
    args=['component','start','dxball','math-support','--interface-intent',str(output/'interface.json'),
        '--assumption-file',str(HERE/'BOUNDARY.md'),'--remove-source','source/component.c','--output',str(output/'authoring')]
    for n in OPS:args+=['--operation-symbol',n+'=lifted_math_'+n]
    for n in ('math.c','math-state.h'):args+=['--source-file','source/'+n+'='+str(HERE/n)]
    ran=subprocess.run([sys.executable,'-m','spaghetti_extractor',*args],capture_output=True,text=True)
    (output/'start.stdout').write_text(ran.stdout);(output/'start.stderr').write_text(ran.stderr)
    if ran.returncode:raise ValueError('inspect start.stderr')
    entries=dict(startup=(0xeaa0,0xeaa8),**{'math_'+n:r for n,r in RANGES.items()})
    (output/'native-image.h').write_text('\n'.join(native_entry_header(original=original,expected_sha256=PE_SHA256,module=None,
        entry_rva=lo,end_rva=hi,installer='install_'+n) for n,(lo,hi) in entries.items()))
    prepare_comparison_package(interface_package=output/'authoring/interface.json',source_files={n:output/'authoring/source'/n for n in ('math.c','math-state.h')},
        operation_symbols={n:'lifted_math_'+n for n in OPS},target_id='dxball',component_id='math-support',
        adapter_files={'runtime.c':HERE/'runtime.c','bridge.c':output/'bridge.c'},
        include_files={**observation_headers(),**native_adapter_headers('pe32-entry-hook.h'),
            'native-image.h':output/'native-image.h','math-runtime.h':output/'math-runtime.h'},
        **native_environment(environment_package),original_files=['runtime/DXBall.exe'],oracle_kind='native-original',cases=CASES,
        observation_fields=['math'],assumptions=[(HERE/'BOUNDARY.md').read_text()],
        scope='Complete table initialization/readers, coordinate projection and pan; explicit neighboring-memory history and normal numeric environment.',
        export_adapters=['adapters/bridge.c'],
        program_driver=dict(kind='pe32-import',image='runtime/DXBall.exe',library='dx-math.dll',symbol='dx_math_anchor'),output=output/'math-support')
    write_json(output/'preparation.json',dict(seconds=time.monotonic()-started,cases=len(CASES),original_source_consulted=False,tool_internal_changes=False))

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for n in ('original','environment_package','output'):p.add_argument(n,type=Path)
    a=p.parse_args();prepare(a.original.resolve(),a.environment_package.resolve(),a.output.resolve())
