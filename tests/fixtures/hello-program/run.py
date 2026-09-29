"""Compare unmodified, instrumented-original and selected normal Hello processes."""
import argparse
import json
import os
from pathlib import Path
import shutil
import time

from spaghetti_extractor.components.comparison_build import observed_command
from spaghetti_extractor.components.comparison_package import load_comparison_package, package_file
from spaghetti_extractor.components.comparison_run import load_comparison_result
from spaghetti_extractor.components.comparison_runtime import check_runtime_inputs, wine_sessions
from spaghetti_extractor.components.comparison_services import service_observations
from spaghetti_extractor.util import sha256_file, write_json

CASES=[('default',[]),('traditional',['-t']),('custom',['-g','A lifted greeting']),
       ('empty',['-g','']),('accent',['-g','caf\u00e9']),('quoted',['-g','a "quoted" \\ greeting']),
       ('long',['-g','q'*1024]),('help',['--help']),('version',['--version']),
       ('unknown',['--not-an-option']),('operand',['extra']),('missing-greeting',['-g'])]


def run(bundle,output,case=None):
    if not os.environ.get('WAYLAND_DISPLAY'):
        raise ValueError('run inside spaghetti-headless-wayland')
    started=time.monotonic();description=json.loads((bundle/'program.json').read_text())
    result=load_comparison_result(bundle/'comparison')
    if result['receipt_sha256']!=description['comparison_receipt_sha256']:
        raise ValueError('program selection comparison has changed')
    for field in ('objects','runtime_files'):
        for name,digest in description[field].items():
            if sha256_file(package_file(bundle,name))!=digest:raise ValueError('changed program input: '+name)
    plan,_=load_comparison_package(bundle/'comparison/inputs')
    output.mkdir(parents=True,exist_ok=False)
    environments={};directories={};bindings={}
    runtime=output/'runtime'
    for side in ('plain','original','source'):
        directory=output/side;shutil.copytree(bundle/'runtime'/side,directory)
        prefix=output/('wine-'+side);prefix.mkdir()
        directories[side]=directory
        bindings[side]={p.name:sha256_file(p) for p in directory.iterdir() if p.is_file()}
        environments[side]={**os.environ,'WINEPREFIX':str(prefix),'WINEPATH':str(runtime),
            'WINEDEBUG':'-all','LC_ALL':'C','SPX_HELLO_PROGRAM_SIDE':side}
    timings=[];observations=[];status='match'
    cases=CASES if case is None else [row for row in CASES if row[0]==case]
    if not cases:raise ValueError('unknown program case')
    with wine_sessions(server=plan['tools']['server']['path'],environments=environments,
            cwd=output,logs=output,timeout=30,timings=timings,persistent=True,
            dispose_prefixes=True,runner=plan['tools']['runner']['path']):
        for identity,args in cases:
            row=dict(id=identity,arguments=args,sides={})
            for side,directory in directories.items():
                prefix=output/(identity+'-'+side)
                report=output/(identity+'-'+side+'.state.json')
                env={**environments[side],'SPX_HELLO_PROGRAM_REPORT':'Z:'+str(report).replace('/','\\')}
                check_runtime_inputs(directory,bindings[side])
                # Wine's CRT uses the resolved executable path even for a relative
                # launch. Use one pathname for all sides, with freshly staged
                # bound files and separate prefixes. Otherwise startup allocation
                # sizes observe the differing source/original directory names.
                if runtime.exists():shutil.rmtree(runtime)
                shutil.copytree(directory,runtime)
                observed=observed_command([plan['tools']['runner']['path'],'hello.exe',*args],
                    cwd=runtime,env=env,timeout=30,output=prefix,phase='execution',timings=timings)
                check_runtime_inputs(runtime,bindings[side])
                if {p.name for p in runtime.iterdir()}!=set(bindings[side]):
                    raise ValueError('unexpected program working-directory mutation')
                if observed['timed_out'] or observed['returncode'] not in (0,1):
                    raise ValueError(f'{identity}/{side}: unexpected execution failure; inspect retained logs')
                state=json.loads(report.read_text()) if side!='plain' else None
                if state is not None and (state['exit_seen']!=1 or state['exit_code']!=observed['returncode']):
                    raise ValueError('normal program exit was not observed')
                if state is not None and state['source']!=(side=='source'):
                    raise ValueError('program executed the wrong component selection')
                raw=prefix.with_suffix('.stderr').read_bytes()
                telemetry=(b'SPX_SERVICE ',b'SPX_SERVICE_SCOPE ',b'SPX_SERVICE_HANDLER ')
                stderr=b''.join(line for line in raw.splitlines(keepends=True) if not line.startswith(telemetry))
                if side=='source':
                    services=service_observations(plan,{'source':prefix.with_suffix('.stderr')})
                    write_json(output/(identity+'-services.json'),services)
                    if services and services['status']!='satisfied':
                        raise ValueError('program service observation failed')
                elif stderr!=raw:raise ValueError('non-source program emitted reserved instrumentation')
                row['sides'][side]=dict(exit_code=observed['returncode'],stdout=list(prefix.with_suffix('.stdout').read_bytes()),
                    stderr=list(stderr),state=state)
            plain,original,source=(row['sides'][name] for name in ('plain','original','source'))
            behavior=lambda item: {k:item[k] for k in ('exit_code','stdout','stderr')}
            if behavior(plain)!=behavior(original):raise ValueError('instrumentation changes original program behavior: '+identity)
            fields=('tls_calls','allocation_events','remaining_allocations','implicit_states')
            row['differences']=[k for k in ('exit_code','stdout','stderr') if original[k]!=source[k]]+[
                'state.'+k for k in fields if original['state'][k]!=source['state'][k]]
            row['status']='mismatch' if row['differences'] else 'match'
            if row['status']!='match':status='mismatch'
            for side in (original,source):
                if [r[1] for r in side['state']['tls_calls']]!=[1,1]:
                    raise ValueError('both original TLS process-attach callbacks must execute exactly once')
            if source['state']['conversion_calls'][3]!=1:
                raise ValueError('normal program entry did not execute the selected state reset')
            observations.append(row)
            write_json(output/'cases.json',observations)
            print(identity,row['status'],source['state']['source_calls'],source['state']['conversion_calls'],flush=True)
    write_json(output/'program-run.json',dict(status=status,seconds=time.monotonic()-started,cases=observations,
        comparison_receipt_sha256=result['receipt_sha256'],program_sha256=sha256_file(bundle/'program.json'),
        original_startup=True,original_tls_observed=True,strong_qualification=False,
        whole_program_portable=False,diagnostic=description['status']=='diagnostic',timings=timings,
        producer_sha256=sha256_file(Path(__file__))))
    return status


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('bundle',type=Path);parser.add_argument('output',type=Path);parser.add_argument('--case')
    args=parser.parse_args()
    raise SystemExit(0 if run(args.bundle.resolve(),args.output.resolve(),args.case)=='match' else 1)
