"""Replay original warning behavior with explicit prior stack contents, without game startup."""
import argparse
import json
import os
from pathlib import Path
import shutil
import time
from spaghetti_extractor.components.comparison_build import observed_command
from spaghetti_extractor.components.comparison_capture import build_capture,capture_command,collect_capture,LAUNCHER
from spaghetti_extractor.components.comparison_environment import native_environment,native_adapter_headers
from spaghetti_extractor.components.comparison_original import native_entry_header
from spaghetti_extractor.components.comparison_pe32_program import add_experimental_import
from spaghetti_extractor.components.comparison_runtime import wine_sessions
from spaghetti_extractor.util import sha256_file,write_json

HERE=Path(__file__).resolve().parent
PE_SHA256='191c113582e1f31016a158d40372fa21ea68d9348bf847bbfbc8e7c7bdfe195f'
HOOKS=dict(startup=0xeaa0,random=0xae20,stop_sound=0x3370,play_sound=0x3210,loop_sound=0x32b0,
    queue=0x6410,explosion=0x6d30,particle=0x7b00,select_bank=0xbd70,pan=0x3550,destination=0xbd60,cell=0x5ad0)

def review_result(result):
    """Check the retained counterexample, without requiring another Wine run."""
    if (result.get('kind')!='native-entry-state-experiment' or result.get('original_sha256')!=PE_SHA256
            or result.get('whole_program_run') is not False or result.get('authored_replacement_selected') is not False):
        raise ValueError('requires the pinned native-only experiment')
    by_tile={}
    for case in result['cases']:
        execution=case['execution']
        if execution['returncode'] or execution['timed_out'] or execution.get('observation_error'):
            raise ValueError('incomplete native observation: '+case['id'])
        row=case['observation'];by_tile.setdefault(row['tile'],[]).append(row)
    if set(by_tile)!={0,5,23,255} or any(len(rows)!=2 for rows in by_tile.values()):
        raise ValueError('requires both retained seeds for all four board states')
    for tile,rows in by_tile.items():
        if {tuple(row['entry_words']) for row in rows}!={(120,2,3),(300,5,7)}:
            raise ValueError('unexpected entry words')
        for row in rows:
            if (row['initial_count']!=int(tile!=0) or row['current_count']!=int(tile==5)
                    or row['remaining']!=int(tile!=0) or row['calls']!=[1,1,15] or row['warning_frames']!=4):
                raise ValueError('native setup or warning execution did not reproduce')
            y,grid_row,column=row['entry_words']
            if (row['queue']!=([1,1] if tile==5 else [column,grid_row])
                    or row['explosion']!=([65,72] if tile==5 else [column,y])):
                raise ValueError('native coordinate dependency did not reproduce')
    control=[{key:value for key,value in row.items() if key!='entry_words'} for row in by_tile[5]]
    if control[0]!=control[1]:raise ValueError('eligible-cell control depends on entry residue')
    return dict(status='missing-boundary-input-reproduced',native_cases=8,
        eligible_cell_control='independent-of-residue',empty_board_cases='depend-on-residue',
        count_hit_counterexamples=[23,255],
        required_entry_words=[dict(offset=-28,role='y'),dict(offset=-24,role='row'),dict(offset=-20,role='column-and-initial-x')],
        offset_base='original-warning-entry-esp',local_reproduction='supported-by-existing-native-adapters',
        portable_caller_state_transport='not-established',whole_game_reachability='not-established',
        replacement_equivalence='not-assessed')

def run(original,output,*,source=None,extra_sources=None,hooks=None,scenarios=None,
        kind='native-entry-state-experiment',review=review_result):
    if sha256_file(original)!=PE_SHA256:raise ValueError('requires the pinned executable')
    source=source or HERE/'entry-residue.c';hooks=HOOKS if hooks is None else hooks
    if scenarios is None:
        scenarios=[(f'tile-{tile}-seed-{residue[2]}',list(map(str,(tile,*residue))))
            for tile in (5,0,23,255) for residue in ((120,2,3),(300,5,7))]
    start=time.monotonic();output.mkdir(parents=True,exist_ok=False);timings=[];tools=native_environment()
    for name,path in {**tools['runtime_files'],**native_adapter_headers('pe32-entry-hook.h')}.items():shutil.copyfile(path,output/name)
    sources={source.name:source,**(extra_sources or {})}
    for name,path in sources.items():shutil.copyfile(path,output/name)
    (output/'native-image.h').write_text('\n'.join(native_entry_header(original=original,expected_sha256=PE_SHA256,
        module=None,entry_rva=address,end_rva=address+8,installer='install_'+name) for name,address in hooks.items()))
    env=dict(os.environ);compiler=str(tools['compiler']);payload=output/'dx-warning-probe.dll'
    compiled=observed_command([compiler,'-std=c11','-O0','-Wall','-Wextra','-Werror','-shared',source.name,'-o',str(payload)],
        cwd=output,env=env,timeout=60,output=output/'compiler',phase='compiler-link',timings=timings)
    if compiled['returncode'] or compiled['timed_out']:raise ValueError('inspect compiler.stderr')
    add_experimental_import(original,payload,'dx_warning_probe_anchor',output/'probe.exe')
    if not build_capture(compiler=compiler,output=output,env=env,timeout=60,timings=timings):raise ValueError('capture build failed')
    prefix=output/'wine';prefix.mkdir(mode=0o700);(output/'tmp').mkdir()
    env.update(WINEPREFIX=str(prefix),WINEPATH=str(output),WINEDEBUG='-all',LC_ALL='C',TMPDIR=str(output/'tmp'))
    cases=[]
    with wine_sessions(server=str(tools['server']),environments={'probe':env},cwd=output,logs=output,timeout=60,
            timings=timings,persistent=True,dispose_prefixes=True,runner=str(tools['runner'])):
        for name,args in scenarios:
            log=output/name
            command,execution_env=capture_command([str(tools['runner']),str(output/'probe.exe'),*args],
                runtime=output,launcher=output/LAUNCHER,env=env,timeout=20)
            executed=observed_command(command,cwd=output,env=execution_env,timeout=20,output=log,phase='execution',timings=timings)
            execution={k:executed[k] for k in ('returncode','timed_out')};collect_capture(runtime=output,prefix=log,execution=execution)
            if execution['returncode'] or execution['timed_out'] or execution.get('observation_error'):raise ValueError(str(execution))
            if log.with_suffix('.stderr').read_bytes():raise ValueError('unexpected application stderr')
            observation=json.loads(log.with_suffix('.stdout').read_text());cases.append(dict(id=name,arguments=args,execution=execution,observation=observation))
    result=dict(kind=kind,original_sha256=PE_SHA256,
        source_sha256=sha256_file(output/source.name),source_files={name:sha256_file(output/name) for name in sources},
        whole_program_run=False,authored_replacement_selected=False,
        seconds=time.monotonic()-start,timings=timings,cases=cases)
    write_json(output/'result.json',result)
    write_json(output/'review.json',review(result))
    for case in cases:print(json.dumps(case['observation']))

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('original',type=Path,nargs='?');parser.add_argument('output',type=Path,nargs='?')
    parser.add_argument('--review',type=Path,help='check an existing result without running Wine')
    args=parser.parse_args()
    if args.review:
        if args.original or args.output:parser.error('--review does not take execution paths')
        print(json.dumps(review_result(json.loads(args.review.read_text())),indent=2))
    else:
        if not args.original or not args.output:parser.error('original and output are required')
        run(args.original.resolve(),args.output.resolve())
