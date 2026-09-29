"""Compare real allocation-failure delivery in the original and source backends."""
import argparse
import json
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import time

from spaghetti_extractor.components.comparison_runtime import wine_sessions
from spaghetti_extractor.util import sha256_file, write_json

ORIGINAL_SHA='50d05ffd1f3cdbb5257f2cda429d9b920d95c091bb88a9d8bcdcb08ae9bacb1d'
CASES=('string-copy','string-empty','string-invalid','array-create','array-set','array-grow','program-string','program-string-cold')


def differing_paths(a,b,prefix=''):
    if isinstance(a,dict) and isinstance(b,dict):
        return [p for k in sorted(a.keys()|b.keys()) for p in differing_paths(a.get(k),b.get(k),prefix+'.'+k)]
    if isinstance(a,list) and isinstance(b,list) and len(a)==len(b):
        return [p for i,(x,y) in enumerate(zip(a,b)) for p in differing_paths(x,y,prefix+'.'+str(i))]
    return [prefix.lstrip('.')] if a!=b else []


def diagnostic_allocations(data):
    """Only the observer's two declared diagnostic records may leave stderr."""
    lines=data.decode('ascii').splitlines()
    if len(lines)!=2 or not lines[0].startswith('physical-allocations=') or not re.fullmatch(
            r'allocation-activity allocations=\d+ releases=\d+ unregistered_releases=\d+',lines[1]):
        raise ValueError('unexpected diagnostic output')
    physical=json.loads(lines[0].split('=',1)[1])
    if not isinstance(physical,dict) or set(physical)!={'live_blocks','live_bytes','invalid_releases','dtoa_context_bytes','live_sizes'}:
        raise ValueError('invalid physical allocation fields')
    if any(type(physical[k]) is not int or physical[k]<0 for k in physical if k!='live_sizes'):
        raise ValueError('invalid physical allocation counts')
    sizes=physical['live_sizes']
    if not isinstance(sizes,list) or any(type(n) is not int or n<0 for n in sizes):
        raise ValueError('invalid live allocation sizes')
    physical['live_sizes']=sorted(sizes)
    return physical


def check_allocation_observation(value,physical,pointer_size):
    """Check the C logical view against its separately retained raw measurements."""
    sizes=list(physical['live_sizes'])
    if len(sizes)!=physical['live_blocks'] or sum(sizes)!=physical['live_bytes']:
        raise ValueError('inconsistent physical allocation observations')
    cold=value.get('case')=='program-string-cold'
    extent=9*pointer_size if cold else 0
    if physical['dtoa_context_bytes']!=extent:
        raise ValueError('numeric context has another physical extent')
    if cold:
        if value.get('dtoa_context')!=dict(created=1,live=True,null_pointer_slots=9):
            raise ValueError('cold numeric context lacks the reviewed live-object observation')
        sizes.remove(extent)
    elif 'dtoa_context' in value:
        raise ValueError('unexpected numeric context observation')
    expected=dict(live_blocks=physical['live_blocks']-int(cold),live_bytes=physical['live_bytes']-extent,
        invalid_releases=physical['invalid_releases'])
    if value['lifetime']!=expected or value['unmapped_live_sizes']!=sizes:
        raise ValueError('logical allocation observations disagree with physical measurements')


def run(build,original,output,runner,server,pe_cc,qemu=None,case=None):
    if not os.environ.get('WAYLAND_DISPLAY'):raise ValueError('requires spaghetti-headless-wayland')
    report=json.loads((build/'build.json').read_text())
    if report['status']!='built' or sha256_file(build/'failure')!=report.get('allocation_failure_sha256'):
        raise ValueError('requires a build with the exact allocation-failure consumer')
    if sha256_file(original/'libjq-1.dll')!=ORIGINAL_SHA:raise ValueError('requires pinned original libjq')
    for name,digest in report['input_sha256s'].items():
        if sha256_file(build/'sources'/name)!=digest:raise ValueError('retained build input changed: '+name)
    machine=struct.unpack_from('<H',(build/'failure').read_bytes(),18)[0]
    if machine not in (62,183) or machine==183 and qemu is None:raise ValueError('requires x86-64 or explicit AArch64 emulator')
    output.mkdir(parents=True,exist_ok=False)
    runtime=output/'runtime';runtime.mkdir()
    original_inputs={}
    for path in sorted(original.glob('*.dll')):
        shutil.copyfile(path,runtime/path.name);original_inputs[path.name]=sha256_file(path)
    headers=build/'sources/diagnostics'
    command=[str(pe_cc),'-O2','-std=c11','-Wall','-Wextra','-Werror',
        '-I'+str(headers),'-I'+str(build/'sources/backends/jq/src'),
        str(headers/'failure.c'),str(headers/'allocation-observer.c'),
        '-L'+str(original.parent/'lib'),'-ljq','-o',str(runtime/'failure.exe')]
    begin=time.monotonic();ran=subprocess.run(command,capture_output=True,timeout=60)
    for channel in ('stdout','stderr'):(output/('compile.'+channel)).write_bytes(getattr(ran,channel))
    write_json(output/'compile.json',dict(command=command,exit_code=ran.returncode,seconds=time.monotonic()-begin,
        compiler_sha256=sha256_file(pe_cc),import_library_sha256=sha256_file(original.parent/'lib/libjq.dll.a')))
    if ran.returncode:raise ValueError('original diagnostic compile failed')
    prefix=output/'wine';prefix.mkdir()
    env={**os.environ,'LC_ALL':'C.UTF-8','WINEDEBUG':'-all','WINEPREFIX':str(prefix),'WINEPATH':str(runtime)}
    for key in ('JQ_LIBRARY_PATH','JQ_COLORS','SPX_COMPONENT_COUNTS','POSIXLY_CORRECT'):env.pop(key,None)
    fontconfig=output/'fontconfig.xml'
    fontconfig.write_text('<?xml version="1.0"?><!DOCTYPE fontconfig SYSTEM "fonts.dtd"><fontconfig></fontconfig>\n')
    env['FONTCONFIG_FILE']=str(fontconfig)
    selected=list(CASES) if case is None else [case]
    write_json(output/'cases.json',selected)
    rows=[];timings=[];begin=time.monotonic()
    with wine_sessions(server=str(server),environments={'original':env},cwd=runtime,logs=output,
            timeout=45,timings=timings,persistent=True,dispose_prefixes=True,runner=str(runner)):
        for name in selected:
            sides={};differences=[]
            for side,command in [('original',[str(runner),'failure.exe',name]),
                    ('portable',([str(qemu)] if machine==183 else [])+[str(build/'failure'),name])]:
                start=time.monotonic();ran=subprocess.run(command,cwd=runtime,env=env,capture_output=True,timeout=30)
                for channel in ('stdout','stderr'):(output/(name+'.'+side+'.'+channel)).write_bytes(getattr(ran,channel))
                row=dict(command=command,seconds=time.monotonic()-start,exit_code=ran.returncode,
                    stdout_sha256=sha256_file(output/(name+'.'+side+'.stdout')),
                    stderr_sha256=sha256_file(output/(name+'.'+side+'.stderr')))
                if ran.returncode: differences.append(side+'.consumer-failed')
                try:
                    row['value']=json.loads(ran.stdout);row['physical_allocations']=diagnostic_allocations(ran.stderr)
                    row['live_sizes']=row['physical_allocations']['live_sizes']
                    check_allocation_observation(row['value'],row['physical_allocations'],4 if side=='original' else 8)
                except (ValueError,UnicodeDecodeError,KeyError,TypeError):differences.append(side+'.invalid-observations')
                sides[side]=row
            a=sides['original'];b=sides['portable']
            physical=differing_paths(a.get('physical_allocations'),b.get('physical_allocations'))
            differences+=differing_paths(a.get('value'),b.get('value'))
            for field in ('exit_code','stdout_sha256'):
                if a.get(field)!=b.get(field):differences.append(field)
            relation=('C observation of one live dtoa context with nine null pointers; exact remaining heap'
                if name=='program-string-cold' and all('value' in s for s in (a,b)) else None)
            rows.append(dict(case=name,status='mismatch' if differences else 'match',differences=differences,
                physical_differences=physical,representation_relation=relation,sides=sides))
            write_json(output/'results.json',rows)
            if differences:
                print(name+': mismatch: '+', '.join(differences),flush=True)
            elif relation:
                print(name+': match with explicit dtoa context layout; physical allocations '
                    +str(a['live_sizes'])+' / '+str(b['live_sizes']),flush=True)
    status='match' if all(r['status']=='match' for r in rows) else 'mismatch'
    write_json(output/'run.json',dict(status=status,cases=len(rows),seconds=time.monotonic()-begin,
        build_sha256=sha256_file(build/'build.json'),executable_sha256=report['allocation_failure_sha256'],
        original_executable_sha256=sha256_file(runtime/'failure.exe'),original_inputs=original_inputs,
        runner=dict(path=str(runner),sha256=sha256_file(runner)),server=dict(path=str(server),sha256=sha256_file(server)),
        emulator=dict(path=str(qemu),sha256=sha256_file(qemu)) if machine==183 else None,
        compile_sha256=sha256_file(output/'compile.json'),results_sha256=sha256_file(output/'results.json'),
        case_inputs_sha256=sha256_file(output/'cases.json'),startup_timings=timings,elf_machine=machine,
        observations='exact stdout and exit status, including the C logical view of the cold dtoa context and remaining heap; '
            'physical allocations retained separately and checked against that view',
        diagnostic_only='total allocation/release/unregistered-release activity; exact stderr retained, unexpected records rejected',
        preconditions=['Real jq nomem handler installed before observing allocations.',
            'Warm program comparison initializes numeric conversion before observation; cold comparison identifies its actual allocation generation and empty pointer slots.',
            'Single-threaded next-malloc injection at selected entry; no claim about physical exhaustion or other allocation failures.'],
        model_seconds=0,solver_seconds=0,strong_qualification=False,whole_jq_lift=False,
        producer_sha256=sha256_file(Path(__file__))))
    print(status,len(rows),'allocation-failure cases',flush=True)
    return status


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('build','original','output'):p.add_argument(name,type=Path)
    for name in ('runner','server','pe-cc'):p.add_argument('--'+name,type=Path,required=True)
    p.add_argument('--qemu',type=Path)
    p.add_argument('--case',choices=CASES)
    a=p.parse_args()
    status=run(a.build.resolve(),a.original.resolve(),a.output.resolve(),a.runner,a.server,a.pe_cc,a.qemu,a.case)
    raise SystemExit(0 if status=='match' else 2)
