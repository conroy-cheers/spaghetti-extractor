"""Edit one graphics unit against x86, reuse neighbors, then check its consumer."""
import argparse
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import time

from spaghetti_extractor.components.comparison_package import load_comparison_package, revise_comparison_package
from spaghetti_extractor.components.comparison_run import load_comparison_result
from spaghetti_extractor.util import sha256_file, write_json
from native import prepare


def workflow(packages, output):
    if not os.environ.get('WAYLAND_DISPLAY'):
        raise ValueError('run inside spaghetti-headless-wayland')
    output.mkdir(parents=True, exist_ok=False)
    commands=[]; results={}; preparations={}

    def command(name, args, expected=0):
        args=list(map(str,args)); started=time.monotonic()
        ran=subprocess.run([sys.executable,'-m','spaghetti_extractor',*args],capture_output=True,text=True,timeout=180)
        (output/(name+'.stdout')).write_text(ran.stdout)
        (output/(name+'.stderr')).write_text(ran.stderr)
        commands.append(dict(name=name,arguments=args,exit_code=ran.returncode,seconds=time.monotonic()-started))
        write_json(output/'commands.json',commands)
        print(name,ran.returncode,round(commands[-1]['seconds'],3),flush=True)
        if ran.returncode!=expected:
            raise RuntimeError(name+': inspect retained stdout/stderr in '+str(output))
        return ran.stdout

    def check(unit, name, *, package=None, previous=None, supplier=None, case=None, expected=0):
        args=['component','check','dxball','graphics-'+unit,'--comparison-package',package or output/unit,'--output',output/name]
        if previous:args+=['--reuse-comparison',output/previous]
        if supplier:args+=['--dependency-package','graphics-reset='+str(supplier)]
        if case:args+=['--case',case]
        text=command(name,args,expected)
        results[name]=load_comparison_result(output/name)
        return results[name],text

    for unit in ('reset','bind','blit','initialize'):
        started=time.monotonic()
        prepare(packages/('graphics-'+unit),output/(unit+'-prepared'))
        preparations[unit]=time.monotonic()-started
        if unit!='initialize':
            command(unit+'-start',['component','start','dxball','graphics-'+unit,
                '--comparison-package',output/(unit+'-prepared'),'--output',output/unit])
            check(unit,unit+'-baseline')
            plan,_=load_comparison_package(output/unit)
            assert not plan.get('dependencies'),unit
            compiled=json.loads((output/(unit+'-baseline')/'build/compilation.json').read_text())
            assert [r['source'] for r in compiled['units'] if r['source'].startswith('source/')]==['source/'+unit+'.c']
            expected=[0,0,0,0]; expected[('reset','bind','blit').index(unit)]=1
            for log in (output/(unit+'-baseline')/'cases').glob('*-source.stderr'):
                counts=[list(map(int,line.split()[1:])) for line in log.read_text().splitlines() if line.startswith('DX_SELECTED ')]
                assert counts==[expected],(unit,counts)

    # The new local oracle declares different experimental premises. Review and
    # adopt those explicitly once; implementation edits thereafter stay local.
    command('consumer-preview',['component','status','dxball','graphics-initialize',
        '--comparison-package',output/'initialize-prepared',
        '--dependency-package','graphics-reset='+str(output/'reset')])
    started=time.monotonic()
    revise_comparison_package(package=output/'initialize-prepared',output=output/'initialize-refined',
        refine_requirements={name:output/name for name in ('reset','bind','blit')})
    refinement_seconds=time.monotonic()-started
    command('consumer-start',['component','start','dxball','graphics-initialize',
        '--comparison-package',output/'initialize-refined','--output',output/'initialize'])
    check('initialize','consumer-baseline',case='seed-1')

    source=output/'reset/source/reset.c'; original=source.read_text()
    old='for (uint32_t slot = 0; slot < 255; ++slot)\n      state->banks[bank].slots[slot] = 0;'
    new='uint32_t remaining = 255;\n    while (remaining != 0)\n      state->banks[bank].slots[--remaining] = 0;'
    assert original.count(old)==1
    compatible=original.replace(old,new); source.write_text(compatible)
    changed,_=check('reset','reset-edited',previous='reset-baseline')
    assert changed['work_counts']['compiler']==1
    for unit in ('bind','blit'):
        reused,_=check(unit,unit+'-reused',previous=unit+'-baseline')
        assert not any(reused['work_counts'].values())
    consumer,_=check('initialize','consumer-edited',previous='consumer-baseline',supplier=output/'reset',case='seed-1')
    assert consumer['work_counts']['compiler']==1

    source.write_text(compatible.replace('remaining = 255','remaining = 254'))
    try:
        wrong,text=check('reset','reset-wrong',previous='reset-edited',case='seed-1',expected=2)
    finally:
        source.write_text(compatible)
    assert wrong['cases'][0]['first_difference']['path']=='$.banks[0][254]'
    replay=next(line.strip()[len('replay: '):] for line in text.splitlines() if line.strip().startswith('replay: '))
    command('replay',shlex.split(replay)[1:],expected=2)
    results['reset-wrong-replay']=load_comparison_result(output/'reset-wrong-replay')
    assert results['reset-wrong-replay']['cases'][0]['first_difference']==wrong['cases'][0]['first_difference']
    assert results['reset-wrong-replay']['work_counts']['compiler']==0
    repaired,_=check('reset','reset-repaired',previous='reset-edited')
    assert not any(repaired['work_counts'].values())
    command('export',['candidate','export','dxball','--comparison',output/'consumer-edited','--output',output/'source-library'])
    started=time.monotonic()
    built=subprocess.run(['make','-C',str(output/'source-library')],capture_output=True,text=True,timeout=60)
    build_seconds=time.monotonic()-started
    (output/'make.stdout').write_text(built.stdout);(output/'make.stderr').write_text(built.stderr)
    if built.returncode:raise RuntimeError('source-library build failed; inspect make.stderr')
    write_json(output/'workflow.json',dict(status='pass',preparation_seconds=preparations,
        refinement_seconds=refinement_seconds,command_seconds=sum(r['seconds'] for r in commands),
        source_library_build_seconds=build_seconds,
        local_neighbors_absent=True,unchanged_neighbors_zero_work=True,
        results={name:dict(status=r['status'],cases=len(r['cases']),receipt_sha256=r['receipt_sha256'],
            work_counts=r['work_counts'],timings=r['timings']) for name,r in results.items()},
        producers={name:sha256_file(Path(__file__).with_name(name)) for name in ('native-workflow.py','native.py','native-runtime.c')},
        new_tool_internals=False,game_startup=False,controlled_services=True,strong_qualification=False))
    print('Independent native component workflow passed',flush=True)


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('packages',type=Path,help='existing reviewed graphics packages from prepare.py')
    parser.add_argument('output',type=Path)
    args=parser.parse_args();workflow(args.packages.resolve(),args.output.resolve())
