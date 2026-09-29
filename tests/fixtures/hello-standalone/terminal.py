"""Compare actual Win32 console cells with standalone output on a UTF-8 terminal."""
import argparse
import json
import os
from pathlib import Path
import platform
import shutil
import struct
import subprocess
import time

from spaghetti_extractor.components.comparison_runtime import wine_sessions
from spaghetti_extractor.util import sha256_file, sha256_text, write_json
from tests.fixtures.native.terminal import terminal_process
from run import cases

HERE=Path(__file__).resolve().parent


def terminal_cases():
    result=[dict(row,streams='both',columns=100,code_page=437) for row in cases()
            if 'stdout_sink' not in row and 'stderr_sink' not in row]
    extra=[('controls','ab\tcd\rZ\nnext\bQ'),('tab-overwrite','abcdef\r\tQ'),
           ('scroll','line\n'*140),('wrap-backspace','x'*100+'\bQ')]
    extra += [(f'wrap-{n}','w'*n) for n in (79,80,99,100,101,199,200,201)]
    extra += [(f'tab-{n}','x'*n+'\tZ') for n in (95,96,97,99,100)]
    extra += [(name,'x'*100+control+'Q') for name,control in
              [('edge-cr','\r'),('edge-lf','\n'),('edge-tab','\t'),('edge-bell','\a'),('edge-two-bs','\b\b')]]
    extra += [('newline-backspace','\n\bQ')]
    result += [dict(id=name,arguments=['-g',text],environment={},streams='both',columns=100,code_page=437)
               for name,text in extra]
    for page in (1252,65001):
        for name,args in [('accent',['-g','caf\u00e9 \u20ac \u201cquotes\u201d']),('error',['--\u00e9'])]:
            result.append(dict(id=f'cp{page}-{name}',arguments=args,environment={},streams='both',columns=100,code_page=page))
    for streams in ('stdout','stderr'):
        for name,args in [('accent',['-g','caf\u00e9 \u20ac']),('error',['--\u00e9'])]:
            result.append(dict(id=f'{streams}-{name}',arguments=args,environment={},streams=streams,columns=100,code_page=437))
    for n in (79,80,81):
        result.append(dict(id=f'width80-{n}',arguments=['-g','w'*n],environment={},streams='both',columns=80,code_page=437))
    for n in range(64,71):
        result.append(dict(id=f'diagnostic-edge-{n}',arguments=['--'+'x'*n+'\bQ'],environment={},streams='both',columns=100,code_page=437))
    return result


def run(build, oracle, output, screen_reader, case=None):
    if not os.environ.get('WAYLAND_DISPLAY'):raise ValueError('run inside spaghetti-headless-wayland')
    report=json.loads((build/'build.json').read_text());original=json.loads((oracle/'oracle.json').read_text())
    if (report['exit_code'] or report.get('entry_profile')!='utf8' or report.get('allocation_fault')
            or sha256_file(build/'hello')!=report['executable_sha256']):
        raise ValueError('requires an unchanged ordinary UTF-8 standalone build')
    raw=(build/'hello').read_bytes();machine=struct.unpack_from('<H',raw,18)[0]
    if raw[:6]!=b'\x7fELF\x02\x01' or machine not in (62,183):raise ValueError('unsupported executable architecture')
    execution=dict(host=platform.machine(),architecture={62:'x86_64',183:'aarch64'}[machine])
    if execution['host']!=execution['architecture']:
        registration=Path('/proc/sys/fs/binfmt_misc')/(execution['architecture']+'-linux')
        text=registration.read_text()
        if not text.startswith('enabled\n'):raise ValueError('architecture execution unavailable')
        interpreter=Path(next(line.split(' ',1)[1] for line in text.splitlines() if line.startswith('interpreter ')))
        execution.update(registration=text,interpreter=str(interpreter),interpreter_sha256=sha256_file(interpreter))
    for name,digest in original['files'].items():
        if sha256_file(oracle/name)!=digest:raise ValueError('original input changed: '+name)
    selected=[row for row in terminal_cases() if case is None or row['id']==case]
    if not selected:raise ValueError('unknown terminal case')
    output.mkdir(parents=True,exist_ok=False);runtime=output/'runtime';runtime.mkdir()
    for path in oracle.glob('*.dll'):shutil.copyfile(path,runtime/path.name)
    observer=HERE.parent/'native/console-launch.c';shutil.copyfile(observer,runtime/observer.name)
    compile_command=[original['command'][0],'-std=c11','-O2','-Wall','-Wextra','-Werror','-c',
        str(runtime/observer.name),'-o',str(runtime/'console-launch.o')]
    before=time.monotonic();compiled=subprocess.run(compile_command,capture_output=True,timeout=60)
    (output/'compile.stdout').write_bytes(compiled.stdout);(output/'compile.stderr').write_bytes(compiled.stderr)
    compiler_seconds=time.monotonic()-before
    if compiled.returncode:raise ValueError('console observer compilation failed')
    link_command=[original['command'][0],'-municode',str(runtime/'console-launch.o'),'-o',str(runtime/'console-launch.exe')]
    before=time.monotonic();linked=subprocess.run(link_command,capture_output=True,timeout=60)
    (output/'link.stdout').write_bytes(linked.stdout);(output/'link.stderr').write_bytes(linked.stderr)
    link_seconds=time.monotonic()-before
    if linked.returncode:raise ValueError('console observer link failed')
    prefix=output/'wine';prefix.mkdir()
    fontconfig=output/'fontconfig.xml'
    fontconfig.write_text('<?xml version="1.0"?><!DOCTYPE fontconfig SYSTEM "fonts.dtd"><fontconfig></fontconfig>\n')
    env={**os.environ,'LC_ALL':'C.UTF-8','WINEDEBUG':'-all','WINEPREFIX':str(prefix),
         'WINEPATH':str(runtime),'FONTCONFIG_FILE':str(fontconfig)}
    for key in ('POSIXLY_CORRECT','SPX_PORTABLE_REPORT','SPX_ORIGINAL_REPORT','SPX_ALLOCATION_FAIL_AT',
                'SPX_ALLOCATION_FAULT_REPORT','SPX_ARGV_REPORT'):
        env.pop(key,None)
    observations=[];timings=[];started=time.monotonic()
    with wine_sessions(server=original['server'],environments={'native':env},cwd=output,logs=output,
            timeout=30,timings=timings,persistent=True,dispose_prefixes=True,runner=original['runner']):
        for row in selected:
            identity=row['id'];environment={**env,**row['environment']};sides={};commands=[]
            before=time.monotonic()
            for side,file in [('plain','plain.exe'),('observed','observed.exe')]:
                shutil.copyfile(oracle/file,runtime/'hello.exe')
                state=output/(identity+'-original-state.json');screen=output/(identity+'-'+side+'-screen.json')
                command=[original['runner'],'console-launch.exe','hello.exe',*row['arguments']]
                ran=subprocess.run(command,cwd=runtime,env={**environment,
                    'SPX_CONSOLE_REPORT':'Z:'+str(screen).replace('/','\\'),
                    'SPX_CONSOLE_STREAMS':row['streams'],'SPX_CONSOLE_CP':str(row['code_page']),
                    'SPX_CONSOLE_COLUMNS':str(row['columns']),
                    'SPX_ORIGINAL_REPORT':'Z:'+str(state).replace('/','\\')},capture_output=True,timeout=40)
                for name in ('stdout','stderr'):(output/(identity+'-'+side+'.'+name)).write_bytes(getattr(ran,name))
                commands.append(command)
                if ran.returncode:raise ValueError('native console observer failed: '+identity)
                value=json.loads(screen.read_text())
                if value['acp']!=1252 or value['code_page']!=row['code_page']:raise ValueError('console code-page profile changed')
                sides[side]={key:value[key] for key in ('exit_code','cursor','lines')}
                sides[side].update(stdout=list(ran.stdout),stderr=list(ran.stderr))
            if sides['plain']!=sides['observed']:raise ValueError('observer changes native console behavior: '+identity)
            native_state=json.loads(state.read_text())
            for side,observe in [('portable',True),('unobserved',False)]:
                state=output/(identity+'-portable-state.json')
                command=['hello.exe',*row['arguments']];commands.append(command)
                value=terminal_process(command,executable=build/'hello',environment={**environment,
                    **({'SPX_PORTABLE_REPORT':str(state)} if observe else {})},cwd=runtime,
                    streams=row['streams'],columns=row['columns'])
                for name in ('stdout','stderr','terminal'):(output/(identity+'-'+side+'.'+name)).write_bytes(value[name])
                rendered=subprocess.run([str(screen_reader),'120',str(row['columns'])],input=value['terminal'],capture_output=True,timeout=10)
                if rendered.returncode:raise ValueError('portable terminal observation unavailable: '+identity)
                sides[side]=dict(json.loads(rendered.stdout),exit_code=value['exit_code'],
                    stdout=list(value['stdout']),stderr=list(value['stderr']))
                write_json(output/(identity+'-'+side+'-screen.json'),sides[side])
            if sides['portable']!=sides['unobserved']:raise ValueError('observer changes portable console behavior: '+identity)
            portable_state=json.loads(state.read_text())
            # Native termination is observed by the launcher; only the portable
            # application report includes its own exit_code field as well.
            if portable_state.pop('exit_code')!=sides['portable']['exit_code']:
                raise ValueError('portable application exit report disagrees with the process')
            match=sides['plain']==sides['portable'] and native_state==portable_state
            differences=[key for key in sides['plain'] if sides['plain'][key]!=sides['portable'][key]]
            if native_state!=portable_state:differences.append('application-state')
            observations.append(dict(case=row,status='match' if match else 'mismatch',differences=differences,
                commands=commands,seconds=time.monotonic()-before))
            write_json(output/'cases.json',observations)
            print(identity,observations[-1]['status'],','.join(differences),flush=True)
    status='match' if all(row['status']=='match' for row in observations) else 'mismatch'
    write_json(output/'terminal-comparison.json',dict(status=status,cases=observations,execution=execution,
        seconds=time.monotonic()-started,compiler_seconds=compiler_seconds,link_seconds=link_seconds,
        compile_command=compile_command,link_command=link_command,timings=timings,model_seconds=0,solver_seconds=0,
        build_sha256=sha256_file(build/'build.json'),executable_sha256=sha256_file(build/'hello'),
        oracle_sha256=sha256_file(oracle/'oracle.json'),screen_reader=str(screen_reader),screen_reader_sha256=sha256_file(screen_reader),
        runner_sha256=sha256_file(Path(original['runner'])),server_sha256=sha256_file(Path(original['server'])),
        environment_sha256=sha256_text(json.dumps(env,sort_keys=True)),
        files={p.relative_to(output).as_posix():sha256_file(p) for p in output.rglob('*') if p.is_file()},
        producer_sha256=sha256_file(Path(__file__)),observer_sha256=sha256_file(observer),
        terminal_process_sha256=sha256_file(HERE.parent/'native/terminal.py'),
        scope='Fresh UTF-8 terminal, column zero, fixed size, one writer; Unicode cells/cursor and redirected bytes; no glyph pixels or attributes',
        strong_qualification=False,whole_terminal_coverage=False))
    return status


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('build','oracle','output','screen_reader'):parser.add_argument(name,type=Path)
    parser.add_argument('--case');args=parser.parse_args()
    raise SystemExit(0 if run(args.build.resolve(),args.oracle.resolve(),args.output.resolve(),args.screen_reader.resolve(),args.case)=='match' else 2)
