"""Compare normal original and standalone processes, raw output and live conversion observations."""
import argparse
import contextlib
import json
import os
import platform
from pathlib import Path
import random
import shutil
import subprocess
import struct
import time

from spaghetti_extractor.components.comparison_runtime import wine_sessions
from spaghetti_extractor.util import sha256_file, write_json


def cases(allocation_fault=False):
    rows=[('default',[]),('traditional',['-t']),('custom',['-g','A lifted greeting']),
        ('empty',['-g','']),('accent',['-g','caf\u00e9']),('quoted',['-g','a "quoted" \\ greeting']),
        ('long',['-g','q'*1024]),('help',['--help']),('version',['--version']),
        ('unknown',['--not-an-option']),('operand',['extra']),('missing-greeting',['-g']),
        ('short-group',['-ttghello']),('long-abbreviation',['--gree=short']),
        ('traditional-abbreviation',['--trad']),('last-custom',['-t','-g','last']),
        ('last-traditional',['-g','first','-t']),('error-then-help',['-x','--help']),
        ('error-then-version',['--wrong','--version']),('operand-then-help',['extra','--help']),
        ('help-then-error',['--help','--wrong']),('help-equals',['--help=no']),
        ('traditional-equals',['--traditional=yes']),('missing-long',['--greeting']),
        ('dash-value',['-g','--help']),('end-options',['--','--help']),('dash-operand',['-']),
        ('double-error',['--bad','-x','tail']),('embedded-newlines',['-g','a\nb\rc\r\nd']),
        ('non-ascii',['-g','\u0080\u00ff\u03b1\u20ac\u3042\U0001f642']),
        ('best-fit-latin',['-g','\u0100\u0110\u0131\u015e\u017f\u01d5']),
        ('best-fit-greek',['-g','\u0391\u03b1\u03b2\u03bc\u03c0']),
        ('best-fit-option',['\uff0d\uff0d\uff47\uff52\uff45\uff45\uff54\uff49\uff4e\uff47=wide option']),
        ('combining',['-g','e\u0301 A\u0304 \u00e9 \u0100']),
        ('unicode-limits',['-g','\u07ff\u0800\ud7ff\ue000\uffff\U00010000\U0010ffff']),
        ('supplementary',['-g','\U0001f642\U0001d11e\U00020000']),
        ('unicode-diagnostic',['\uff0d\uff0d\uff42\uff41\uff44']),
        ('unicode-operand',['\u0100\u03b1\u20ac']),
        ('unicode-option-operand',['operand','\uff0d\uff0d\uff48\uff45\uff4c\uff50'])]
    result=[dict(id=name,arguments=args,environment={}) for name,args in rows]
    result.append(dict(id='posix-stop',arguments=['extra','--help'],environment={'POSIXLY_CORRECT':'1'}))
    byte_text=''
    for value in range(1,256):
        try:byte_text+=bytes([value]).decode('cp1252')
        except UnicodeDecodeError:byte_text+=chr(value)
    result.append(dict(id='codepage-byte-sweep',arguments=['-g',byte_text],environment={}))
    result.extend([
        dict(id='stdout-full',arguments=[],environment={},stdout_sink='full'),
        dict(id='help-stdout-full',arguments=['--help'],environment={},stdout_sink='full'),
        dict(id='stdout-broken-pipe',arguments=[],environment={},stdout_sink='broken-pipe'),
        dict(id='long-broken-pipe',arguments=['-g','q'*8192],environment={},stdout_sink='broken-pipe'),
        dict(id='pipe-buffer-last-byte',arguments=['-g','q'*4095],environment={},stdout_sink='broken-pipe'),
        dict(id='pipe-buffer-overflow',arguments=['-g','q'*4096],environment={},stdout_sink='broken-pipe'),
        dict(id='pipe-buffer-crlf',arguments=['-g','\n'*4095],environment={},stdout_sink='broken-pipe'),
        dict(id='help-broken-pipe',arguments=['--help'],environment={},stdout_sink='broken-pipe'),
        dict(id='stderr-full',arguments=['--wrong'],environment={},stderr_sink='full')])
    rng=random.Random(0x20260922)
    for i in range(32):
        text=''.join(rng.choice(' abcXYZ-\n\t\r\"\\\u0080\u00e9\u3042') for _ in range(rng.randrange(0,90)))
        forms=[['-g',text],['--greeting='+text],['-tg'+text],['--gree',text,'-t']]
        result.append(dict(id=f'generated-{i:02d}',arguments=forms[i%4],environment={}))
    if not allocation_fault:return result
    source={row['id']:row for row in result}
    selected=[]
    for name in ('default','traditional','empty','accent','non-ascii','best-fit-option','long',
            'stdout-full','stdout-broken-pipe','help','version','unknown','operand'):
        attempts=0 if name in ('help','version','unknown','operand') else 1
        selected.append(dict(source[name],id='allocation-'+name,fail_at=1,
            expected_attempts=attempts,expected_failures=attempts))
    selected.append(dict(source['default'],id='allocation-stderr-full',stderr_sink='full',
        fail_at=1,expected_attempts=1,expected_failures=1))
    for name in ('default','non-ascii'):
        selected.append(dict(source[name],id='allocation-disabled-'+name,fail_at=0,
            expected_attempts=1,expected_failures=0))
    selected.append(dict(source['default'],id='allocation-second-unreached',fail_at=2,
        expected_attempts=1,expected_failures=0))
    return selected


def run(build, oracle, output, case=None):
    if not os.environ.get('WAYLAND_DISPLAY'):raise ValueError('run inside spaghetti-headless-wayland')
    build_report=json.loads((build/'build.json').read_text())
    entry=build_report.get('entry_profile','target')
    if entry not in ('target','utf8'):raise ValueError('unknown argument entry profile')
    allocation_fault=build_report.get('allocation_fault',False)
    original=json.loads((oracle/'oracle.json').read_text())
    if build_report['exit_code'] or sha256_file(build/'hello')!=build_report['executable_sha256']:
        raise ValueError('standalone executable binding changed')
    executable_bytes=(build/'hello').read_bytes()
    if executable_bytes[:6]!=b'\x7fELF\x02\x01':raise ValueError('requires a little-endian ELF64 build')
    machine=struct.unpack_from('<H',executable_bytes,18)[0]
    architecture={62:'x86_64',183:'aarch64'}.get(machine)
    if architecture is None:raise ValueError('architecture not yet exercised by this recipe')
    execution=dict(host=platform.machine(),architecture=architecture)
    if architecture!=platform.machine():
        registration=Path('/proc/sys/fs/binfmt_misc')/(architecture+'-linux')
        text=registration.read_text()
        if not text.startswith('enabled\n'):raise ValueError('architecture execution is unavailable')
        interpreter=Path(next(row.split(' ',1)[1] for row in text.splitlines() if row.startswith('interpreter ')))
        execution.update(registration=text,interpreter=str(interpreter),interpreter_sha256=sha256_file(interpreter))
    for name,digest in original['files'].items():
        if sha256_file(oracle/name)!=digest:raise ValueError('original input changed: '+name)
    output.mkdir(parents=True,exist_ok=False)
    runtime=output/'runtime';runtime.mkdir()
    for path in oracle.glob('*.dll'):shutil.copyfile(path,runtime/path.name)
    shutil.copyfile(oracle/'launch.exe',runtime/'launch.exe')
    prefix=output/'wine';prefix.mkdir()
    fontconfig=output/'fontconfig.xml'
    fontconfig.write_text('<?xml version="1.0"?><!DOCTYPE fontconfig SYSTEM "fonts.dtd"><fontconfig></fontconfig>\n')
    env={**os.environ,'LC_ALL':'C.UTF-8','WINEDEBUG':'-all','WINEPREFIX':str(prefix),
         'WINEPATH':str(runtime),'FONTCONFIG_FILE':str(fontconfig)}
    env.pop('POSIXLY_CORRECT',None)
    for key in ('SPX_PORTABLE_REPORT','SPX_ORIGINAL_REPORT','SPX_ALLOCATION_FAIL_AT','SPX_ALLOCATION_FAULT_REPORT'):
        env.pop(key,None)
    selected=[row for row in cases(allocation_fault) if case is None or row['id']==case]
    if not selected:raise ValueError('unknown case')
    timings=[];observations=[];started=time.monotonic()
    argv0='Z:'+str(runtime/'hello.exe').replace('/','\\')

    def execute(name, command, environment, executable=None, stdout_sink='pipe',stderr_sink='pipe'):
        begin=time.monotonic()
        with contextlib.ExitStack() as resources:
            stdout=stderr=subprocess.PIPE
            if stdout_sink=='full':stdout=resources.enter_context(open('/dev/full','wb'))
            if stdout_sink=='broken-pipe':
                read,write=os.pipe();os.close(read);stdout=write;resources.callback(os.close,write)
            if stderr_sink=='full':stderr=resources.enter_context(open('/dev/full','wb'))
            result=subprocess.run(command,executable=executable,cwd=runtime,env=environment,
                stdout=stdout,stderr=stderr,timeout=30)
        raw_out=result.stdout or b'';raw_err=result.stderr or b''
        (output/(name+'.stdout')).write_bytes(raw_out);(output/(name+'.stderr')).write_bytes(raw_err)
        row=dict(command=[os.fsdecode(arg) for arg in command],argument_bytes=[os.fsencode(arg).hex() for arg in command],
            executable=executable,stdout_sink=stdout_sink,stderr_sink=stderr_sink,
            seconds=time.monotonic()-begin,exit_code=result.returncode)
        write_json(output/(name+'.command.json'),row)
        return dict(exit_code=result.returncode,stdout=list(raw_out),stderr=list(raw_err))

    with wine_sessions(server=original['server'],environments={'native':env},cwd=output,logs=output,
            timeout=30,timings=timings,persistent=True,dispose_prefixes=True,runner=original['runner']):
        for row in selected:
            identity=row['id'];arguments=row['arguments'];environment={**env,**row['environment']}
            sinks={key:row.get(key,'pipe') for key in ('stdout_sink','stderr_sink')}
            sides={};faults={}

            def fault_environment(side,windows):
                if not allocation_fault:return {}
                path=str(output/(identity+'-'+side+'-fault.json'))
                return dict(SPX_ALLOCATION_FAIL_AT=str(row['fail_at']),
                    SPX_ALLOCATION_FAULT_REPORT='Z:'+path.replace('/','\\') if windows else path)

            def fault_observation(side):
                if allocation_fault:
                    faults[side]=json.loads((output/(identity+'-'+side+'-fault.json')).read_text())

            images=[('plain','fault.exe'),('observed','fault-observed.exe')] if allocation_fault else [('plain','plain.exe'),('observed','observed.exe')]
            for side,file in images:
                shutil.copyfile(oracle/file,runtime/'hello.exe')
                report=output/(identity+'-original-state.json')
                argv_report=output/(identity+'-'+side+'-argv.json')
                side_env={**environment,'SPX_ORIGINAL_REPORT':'Z:'+str(report).replace('/','\\'),
                    'SPX_ARGV_REPORT':'Z:'+str(argv_report).replace('/','\\'),**fault_environment(side,True)}
                sides[side]=execute(identity+'-'+side,[original['runner'],'launch.exe',argv0,*arguments],side_env,**sinks)
                fault_observation(side)
            if sides['plain']!=sides['observed']:
                raise ValueError('observation changes original behavior for '+identity)
            if allocation_fault:
                if faults['plain']!=faults['observed']:raise ValueError('observer changes allocation fault for '+identity)
                for key,value in [('fail_at',row['fail_at']),('attempts',row['expected_attempts']),('failures',row['expected_failures'])]:
                    if faults['plain'][key]!=value:raise ValueError('original allocation fault '+key+' differs for '+identity)
                if row['fail_at']==0:
                    # Disabled fault machinery must also match the untouched PE.
                    shutil.copyfile(oracle/'plain.exe',runtime/'hello.exe')
                    untouched_env={**environment,'SPX_ARGV_REPORT':'Z:'+str(output/(identity+'-untouched-argv.json')).replace('/','\\')}
                    sides['untouched']=execute(identity+'-untouched',[original['runner'],'launch.exe',argv0,*arguments],untouched_env,**sinks)
                    if sides['untouched']!=sides['plain']:raise ValueError('disabled allocation fault changes original behavior for '+identity)
            native_state=json.loads((output/(identity+'-original-state.json')).read_text())
            if allocation_fault:
                expected=row['expected_failures']
                if native_state['fatal_entries']!=expected or native_state['fatal_errno']!=(12 if expected else 0):
                    raise ValueError('original fatal entry/errno differs for '+identity)
                if native_state['allocations']!=faults['plain']['attempts'] or native_state['allocated_bytes']!=faults['plain']['last_size']:
                    raise ValueError('original fault is outside the observed allocation boundary for '+identity)
            # The launcher computes the shared narrow-byte inputs with Windows'
            # argument service before application execution. It uses no Hello
            # body or output. Verify it against actual original main entry.
            mapping=json.loads((output/(identity+'-plain-argv.json')).read_text())
            if mapping!=json.loads((output/(identity+'-observed-argv.json')).read_text()):
                raise ValueError('argument transport changed between original runs')
            if mapping['code_page']!=1252 or native_state['argv_hex']!=mapping['argv_hex']:
                raise ValueError('Windows input transport differs from the declared entry for '+identity)
            narrow=[bytes.fromhex(value) for value in mapping['argv_hex']]
            portable_arguments=narrow if entry=='target' else [value.encode('utf-8') for value in (argv0,*arguments)]
            report=output/(identity+'-portable-state.json')
            sides['portable']=execute(identity+'-portable',portable_arguments,
                {**environment,'LC_ALL':'C','SPX_PORTABLE_REPORT':str(report),**fault_environment('portable',False)},str(build/'hello'),**sinks)
            fault_observation('portable')
            sides['portable-unobserved']=execute(identity+'-portable-unobserved',portable_arguments,
                {**environment,'LC_ALL':'C',**fault_environment('portable-unobserved',False)},str(build/'hello'),**sinks)
            fault_observation('portable-unobserved')
            if sides['portable']!=sides['portable-unobserved']:
                raise ValueError('observation changes portable behavior for '+identity)
            if allocation_fault and faults['portable']!=faults['portable-unobserved']:
                raise ValueError('observer changes portable allocation fault for '+identity)
            portable_state=json.loads(report.read_text())
            if portable_state['exit_code']!=sides['portable']['exit_code']:
                raise ValueError('portable exit observation differs for '+identity)
            differences=[key for key in ('exit_code','stdout','stderr') if sides['plain'][key]!=sides['portable'][key]]
            differences+=['state.'+key for key,value in native_state.items() if value!=portable_state.get(key)]
            if allocation_fault:
                differences+=['fault.'+key for key,value in faults['plain'].items() if value!=faults['portable'].get(key)]
            observation=dict(**row,input_transport=mapping,sides=sides,native_state=native_state,portable_state=portable_state,differences=differences)
            if allocation_fault:observation['faults']=faults
            observations.append(observation);write_json(output/'cases.json',observations)
            print(identity,'mismatch '+str(differences) if differences else 'match',flush=True)
    status='mismatch' if any(row['differences'] for row in observations) else 'match'
    write_json(output/'run.json',dict(status=status,cases=observations,seconds=time.monotonic()-started,
        argv0_transport=argv0,environment={'launcher_LC_ALL':'C.UTF-8','child_LC_ALL':'C','FONTCONFIG_FILE':str(fontconfig)},
        entry_profile=entry,allocation_fault=allocation_fault,
        fault_scope=original.get('fault_scope') if allocation_fault else None,
        input_transport=('Windows ACP1252 mapping before application execution, checked at original main entry; identical narrow bytes supplied to the portable process.' if entry=='target' else
            'Original Unicode arguments supplied as UTF-8; the portable entry adapter must produce the actual original main-entry narrow bytes without runtime Windows services.'),
        fontconfig_sha256=sha256_file(fontconfig),build_sha256=sha256_file(build/'build.json'),
        executable_sha256=sha256_file(build/'hello'),oracle_sha256=sha256_file(oracle/'oracle.json'),
        timings=timings,source_uses_original_bodies=False,architecture=architecture,execution=execution,
        strong_qualification=False,backend_scope='Windows-1252 narrow arguments and single-byte conversion',producer_sha256=sha256_file(Path(__file__))))
    return status


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('build','oracle','output'):p.add_argument(name,type=Path)
    p.add_argument('--case');a=p.parse_args()
    raise SystemExit(0 if run(a.build.resolve(),a.oracle.resolve(),a.output.resolve(),a.case)=='match' else 1)
