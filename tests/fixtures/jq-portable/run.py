"""Compare untouched PE32 jq with the portable subsystem through normal program entry."""
import argparse
import json
import os
from pathlib import Path
import random
import re
import shutil
import struct
import subprocess
import time
from spaghetti_extractor.components.comparison_runtime import wine_sessions
from spaghetti_extractor.util import sha256_file, write_json

ORIGINAL_SHA='50d05ffd1f3cdbb5257f2cda429d9b920d95c091bb88a9d8bcdcb08ae9bacb1d'


def cases():
    rows=[]
    def add(name,program,value=None,args=(),raw=None):
        data=json.dumps(value,ensure_ascii=False,separators=(',',':')).encode()+b'\n' if raw is None else raw
        rows.append(dict(id=name,arguments=['--binary','-c',*args,program],stdin_hex=data.hex()))
    add('null','.')
    add('array-index','[.[-1],.[0],.[2],.[99],.[-99]]',[1,{'x':[2,3]},4])
    add('array-slices','[.[1:4],.[-3:],.[:0],.[99:],.[-99:2],.]',list(range(8)))
    add('shared-array-update','. as $old | .[1]=[4,5] | [$old,.,.[]]',[1,[2,3],4])
    add('slice-update','. as $old | .[1:3]=[9,8,7] | [$old,.]',list(range(6)))
    add('nested-array-alias','. as $old | .[0][0]=77 | [$old,.]',[[1,2],[3,4]])
    add('array-growth','reduce range(0;2000) as $i ([]; .[$i]=$i) | [length,.[1700:1708],.[-1]]')
    add('array-gap','setpath(["items",18,"name"];"grown")',{'items':[]})
    add('nested-paths','. as $old | setpath(["a",1,"b"];[9,8]) | [$old,.,getpath(["a",1,"b",-1])]',{'a':[0,{'b':[1,2]}]})
    add('root-path','[getpath([]),setpath([];42)]',{'a':[1]})
    add('absent-path','[getpath(["a",5,"x"]),setpath(["b",0];7)]',{'a':[]})
    add('invalid-path','[try getpath(1) catch .,try setpath("x";4) catch .]',{'a':[1]})
    add('deep-path','try getpath([range(0;10001)]) catch .',{})
    add('type-errors','[try .[0] catch .,try .["x"] catch .,try setpath([0];1) catch .]',True)
    add('index-errors','[try .["field"] catch .,try .[{}] catch .,try .[-99]=1 catch .]',[1,2])
    add('object-array-destruction','[range(0;200)|{x:[.,[.,tostring]],y:{z:[.]}}] | .[40:50] | map(.x[1][0])')
    add('string-slices','[.[0:1],.[1:4],.[-2:],.[2:2],.[99:],.[-99:2],.]','café\u0000日本🙂end')
    add('string-byte-frontier','[.[0:1],.[1:2],.[2:3],.[3:4],.[-1:]]','aé中🙂')
    add('string-empty','[.[0:9],.[-3:2],.]','')
    add('string-index-error','[try .[0] catch .,try .[1:2]="x" catch .]','abcd')
    add('regex-backend','[scan("[[:alpha:]]+"),gsub("[0-9]+";"N")]','alpha 123 beta 4')
    add('stream-paths','.',args=('--stream',),value={'a':[1,{'b':'café🙂'}],'z':False})
    add('slurp','map(.x)|add',args=('--slurp',),raw=b'{"x":[1,2]}\n{"x":[3,4]}\n')
    add('raw-lines','[.,.[1:4]]',args=('--raw-input',),raw='aé中🙂\nnext\r\n'.encode())
    add('exit-false','false',args=('--exit-status',))
    add('exit-null','null',args=('--exit-status',))
    add('exit-empty','empty',args=('--exit-status',))
    add('parse-error','.',raw=b'{"x":[1,2,}\n')
    add('runtime-error','.["x"]',value=7)
    add('error-after-output','. , error("after output")',value={'a':[1,2]})
    add('input-filename','try input_filename catch .',value={'x':1})
    add('input-line-number','try input_line_number catch .',value={'x':1})
    add('input-stream-callback','[.,inputs]',raw=b'1\n2\n3\n')
    add('utf8-input','[.,.[0:2]]',raw=b'"a\xffb"\n')
    add('args','[$name,($data|setpath(["a",0];5))]',args=('--arg','name','café🙂','--argjson','data','{"a":[1]}'))
    add('slurpfile','[$values,($values[1]|getpath(["a",0]))]',args=('--slurpfile','values','values.json'))
    add('reduce-workload','group_by(.kind)|map({kind:.[0].kind,n:length,total:(map(.n)|add),sample:.[0:3]})',
        value=[{'kind':'k'+str(i%13),'n':i,'tags':['α','β',str(i)]} for i in range(500)])
    rng=random.Random(0x20260922)
    for i in range(24):
        a=[{'n':rng.randrange(-1000,1000),'s':''.join(rng.choice('abé中🙂') for _ in range(rng.randrange(1,12)))} for _ in range(rng.randrange(1,15))]
        index=rng.randrange(len(a));start=rng.randrange(-12,12);end=rng.randrange(start,16)
        program=f'. as $old | setpath(["a",{index},"n"];{i}) | [$old,getpath(["a",{index}]),.a[{index}].s[{start}:{end}],.a[1:4]]'
        add(f'generated-{i:02d}',program,{'a':a})
    return rows


def selected_cases(case, case_files):
    rows=cases()
    names={row['id'] for row in rows}
    for path in case_files:
        extra=json.loads(path.read_text())
        if not isinstance(extra,list) or not extra:
            raise ValueError('case file must contain a nonempty array: '+str(path))
        for row in extra:
            if (not isinstance(row,dict) or set(row)!={'id','arguments','stdin_hex'}
                    or not isinstance(row['id'],str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]*',row['id'])
                    or row['id'] in names or not isinstance(row['arguments'],list)
                    or not all(isinstance(arg,str) and '\0' not in arg for arg in row['arguments'])
                    or not isinstance(row['stdin_hex'],str)):
                raise ValueError('invalid or duplicate program case in '+str(path))
            bytes.fromhex(row['stdin_hex'])
            names.add(row['id']);rows.append(row)
    selected=[row for row in rows if case is None or row['id']==case]
    if not selected:raise ValueError('unknown case')
    return selected


def run(build,original,output,runner,server,qemu=None,case=None,pe_cc=None,case_files=(),runtime_files=(),drive_mappings=(),unc_root=None):
    if not os.environ.get('WAYLAND_DISPLAY'): raise ValueError('requires spaghetti-headless-wayland')
    rows=selected_cases(case,case_files)
    report=json.loads((build/'build.json').read_text())
    if report['status']!='built' or sha256_file(build/'jq')!=report['executable_sha256']:
        raise ValueError('portable executable binding changed')
    if sha256_file(original/'libjq-1.dll')!=ORIGINAL_SHA: raise ValueError('requires pinned original libjq')
    machine=struct.unpack_from('<H',(build/'jq').read_bytes(),18)[0]
    if machine not in (62,183) or machine==183 and qemu is None:
        raise ValueError('requires x86-64 or explicit AArch64 emulator')
    output.mkdir(parents=True,exist_ok=False)
    runtime=output/'runtime';runtime.mkdir()
    original_inputs={}
    for path in sorted(original.glob('*')):
        if path.suffix.lower() not in ('.exe','.dll'):continue
        shutil.copyfile(path,runtime/path.name);original_inputs[path.name]=sha256_file(path)
    (runtime/'values.json').write_text('{"a":[1,2]}\n{"a":[3,4]}\n')
    fixture_inputs={}
    for item in runtime_files:
        name,separator,source=item.partition('=')
        if not separator or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]*',name) or (runtime/name).exists():
            raise ValueError('runtime file needs a unique simple NAME=PATH: '+item)
        source=Path(source).resolve()
        shutil.copyfile(source,runtime/name)
        fixture_inputs[name]=dict(source=str(source),sha256=sha256_file(runtime/name))
    if 'live_values_sha256' not in report or sha256_file(build/'live-values')!=report['live_values_sha256']:
        raise ValueError('build lacks the exact live-value consumer')
    pe_cc=Path(pe_cc or shutil.which('i686-w64-mingw32-gcc') or '')
    if not pe_cc.is_file():raise ValueError('requires --pe-cc or the lifting shell PE32 compiler')
    probe_compile=[str(pe_cc),'-O2','-std=c11','-Wall','-Wextra','-Werror',
        '-I'+str(build/'sources/backends/jq/src'),str(build/'sources/bindings/live-values.c'),
        '-L'+str(original.parent/'lib'),'-ljq','-o',str(runtime/'live-values.exe')]
    compile_started=time.monotonic()
    compiled=subprocess.run(probe_compile,capture_output=True,timeout=60)
    (output/'probe-compile.stdout').write_bytes(compiled.stdout);(output/'probe-compile.stderr').write_bytes(compiled.stderr)
    write_json(output/'probe-compile.json',dict(command=probe_compile,exit_code=compiled.returncode,
        seconds=time.monotonic()-compile_started,compiler_sha256=sha256_file(pe_cc)))
    if compiled.returncode:raise ValueError('original live-value consumer compile failed')
    prefix=output/'wine';prefix.mkdir()
    env={**os.environ,'LC_ALL':'C.UTF-8','WINEDEBUG':'-all','WINEPREFIX':str(prefix),'WINEPATH':str(runtime)}
    for key in list(env):
        if key.startswith('SPX_WINDOWS_'):env.pop(key)
    namespace={}
    for item in drive_mappings:
        drive,separator,path=item.partition('=');drive=drive.upper()
        if not separator or not re.fullmatch('[A-Z]',drive) or drive in ('C','Z') or drive in namespace:
            raise ValueError('drive mapping needs a unique non-system LETTER=PATH: '+item)
        directory=Path(path).resolve()
        if not directory.is_dir():raise ValueError('drive mapping requires an existing directory: '+path)
        namespace[drive]=str(directory);env['SPX_WINDOWS_DRIVE_'+drive]=str(directory)
    if unc_root is not None:
        unc_root=unc_root.resolve()
        if not unc_root.is_dir():raise ValueError('UNC mapping requires an existing directory')
        namespace['unc']=str(unc_root);env['SPX_WINDOWS_UNC_ROOT']=str(unc_root)
    namespace_files={key:{str(p.relative_to(Path(path))):sha256_file(p) for p in sorted(Path(path).rglob('*')) if p.is_file()}
                     for key,path in namespace.items()}
    for key in ('JQ_LIBRARY_PATH','JQ_COLORS','SPX_COMPONENT_COUNTS','POSIXLY_CORRECT'):env.pop(key,None)
    fontconfig=output/'fontconfig.xml';fontconfig.write_text('<?xml version="1.0"?><!DOCTYPE fontconfig SYSTEM "fonts.dtd"><fontconfig></fontconfig>\n')
    env['FONTCONFIG_FILE']=str(fontconfig)
    write_json(output/'cases.json',rows)
    results=[];timings=[];totals={};started=time.monotonic()
    with wine_sessions(server=str(server),environments={'original':env},cwd=runtime,logs=output,
            timeout=45,timings=timings,persistent=True,dispose_prefixes=True,runner=str(runner)):
        for name,path in namespace.items():
            link=prefix/'dosdevices'/('unc' if name=='unc' else name.lower()+':')
            if link.exists() or link.is_symlink():raise ValueError('namespace mapping is already present: '+str(link))
            link.symlink_to(path,target_is_directory=True)
        for row in rows:
            sides={};name=row['id'];counts=output/(name+'.counts.json')
            for side in ('original','portable'):
                command=([str(runner),'jq.exe'] if side=='original' else
                    ([str(qemu)] if machine==183 else [])+[str(build/'jq')])+row['arguments']
                begin=time.monotonic()
                ran=subprocess.run(command,input=bytes.fromhex(row['stdin_hex']),cwd=runtime,
                    env={**env,**({'SPX_COMPONENT_COUNTS':str(counts)} if side=='portable' else {})},
                    capture_output=True,timeout=30)
                for channel in ('stdout','stderr'):(output/(name+'.'+side+'.'+channel)).write_bytes(getattr(ran,channel))
                sides[side]=dict(command=command,seconds=time.monotonic()-begin,exit_code=ran.returncode,
                    stdout_sha256=sha256_file(output/(name+'.'+side+'.stdout')),
                    stderr_sha256=sha256_file(output/(name+'.'+side+'.stderr')))
            differences=[key for key in ('exit_code','stdout_sha256','stderr_sha256') if sides['original'][key]!=sides['portable'][key]]
            if not counts.exists():differences.append('missing-portable-entry-observations')
            else:
                observed=json.loads(counts.read_text())
                for identity,count in observed.items():totals[identity]=totals.get(identity,0)+count
            results.append(dict(id=name,status='mismatch' if differences else 'match',differences=differences,sides=sides))
            write_json(output/'results.json',results)
            if differences:print(name,differences,flush=True)
        probe_sides={}
        for side,command in [('original',[str(runner),'live-values.exe']),
            ('portable',([str(qemu)] if machine==183 else [])+[str(build/'live-values')])]:
            ran=subprocess.run(command,cwd=runtime,env=env,capture_output=True,timeout=30)
            for channel in ('stdout','stderr'):(output/('live-values.'+side+'.'+channel)).write_bytes(getattr(ran,channel))
            probe_sides[side]=dict(exit_code=ran.returncode,
                stdout_sha256=sha256_file(output/('live-values.'+side+'.stdout')),
                stderr_sha256=sha256_file(output/('live-values.'+side+'.stderr')))
        probe_differences=[k for k in probe_sides['original'] if probe_sides['original'][k]!=probe_sides['portable'][k]]
        if probe_sides['original']['exit_code'] or probe_sides['portable']['exit_code']:probe_differences.append('consumer-failed')
    status='match' if all(r['status']=='match' for r in results) else 'mismatch'
    if probe_differences:status='mismatch'
    expected=set(json.loads((build/'sources/lifted/source-export.json').read_text())['components'])
    if case is None and (set(totals)!=expected or not all(totals.values())):raise ValueError('normal program cases did not reach every selected component')
    write_json(output/'run.json',dict(status=status,seconds=time.monotonic()-started,cases=len(results),
        original_inputs=original_inputs,build_sha256=sha256_file(build/'build.json'),
        executable_sha256=report['executable_sha256'],elf_machine=machine,
        runner=dict(path=str(runner),sha256=sha256_file(runner)),server=dict(path=str(server),sha256=sha256_file(server)),
        emulator=dict(path=str(qemu),sha256=sha256_file(qemu)) if machine==183 else None,
        component_calls=totals,startup_timings=timings,case_inputs_sha256=sha256_file(output/'cases.json'),
        results_sha256=sha256_file(output/'results.json'),observations='exact stdout, stderr, exit status; portable selected-entry counters',
        live_values=dict(status='mismatch' if probe_differences else 'match',differences=probe_differences,
            sides=probe_sides,original_sha256=sha256_file(runtime/'live-values.exe'),
            portable_sha256=report['live_values_sha256'],source_sha256=sha256_file(build/'sources/bindings/live-values.c'),
            cases=32,observations='logical contents, live pointer alias relations, native reference counts and effects of releasing shared views'),
        environment={'LC_ALL':'C.UTF-8','original_binary_stream_option':all('--binary' in row['arguments'] for row in rows),'headless_wayland':True},
        fixture_inputs=fixture_inputs,namespace=namespace,namespace_files=namespace_files,
        strong_qualification=False,whole_jq_lift=False,producer_sha256=sha256_file(Path(__file__))))
    print(status,len(results),'normal-entry cases',flush=True)
    return status


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('build','original','output'):p.add_argument(name,type=Path)
    for name in ('runner','server'):p.add_argument('--'+name,type=Path,required=True)
    p.add_argument('--qemu',type=Path);p.add_argument('--case');p.add_argument('--pe-cc',type=Path)
    p.add_argument('--case-file',type=Path,action='append',default=[],help='append operator cases with id, arguments and stdin_hex')
    p.add_argument('--runtime-file',action='append',default=[],metavar='NAME=PATH',help='retain an additional input file for both program sides')
    p.add_argument('--drive-mapping',action='append',default=[],metavar='LETTER=PATH',help='map the same host directory in Wine and the portable namespace')
    p.add_argument('--unc-root',type=Path,help='map a directory containing server/share trees on both sides')
    a=p.parse_args()
    status=run(a.build.resolve(),a.original.resolve(),a.output.resolve(),a.runner,a.server,a.qemu,a.case,a.pe_cc,a.case_file,a.runtime_file,a.drive_mapping,a.unc_root)
    raise SystemExit(0 if status=='match' else 2)
