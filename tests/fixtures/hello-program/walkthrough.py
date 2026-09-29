"""Public C edit/check/reuse through normal Hello entry, discrepancy and repair."""
import argparse
import os
from pathlib import Path
import shlex
import subprocess
import sys
import time

from spaghetti_extractor.components.comparison_package import load_comparison_package
from spaghetti_extractor.components.comparison_run import load_comparison_result
from spaghetti_extractor.util import sha256_file, write_json
from comparison import prepare


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    names=('local_package','native_package','neighbor_package','observer','output')
    for name in names:parser.add_argument(name,type=Path)
    args=parser.parse_args()
    if not os.environ.get('WAYLAND_DISPLAY'):raise ValueError('run inside spaghetti-headless-wayland')
    local,native,neighbor,observer,out=[getattr(args,n).resolve() for n in names]
    out.mkdir(parents=True,exist_ok=False);started=time.monotonic();commands=[];results={}

    def command(name,arguments,expected=0):
        invocation=[sys.executable,'-m','spaghetti_extractor',*map(str,arguments)];before=time.monotonic()
        result=subprocess.run(invocation,capture_output=True,text=True,timeout=180)
        (out/(name+'.stdout')).write_text(result.stdout);(out/(name+'.stderr')).write_text(result.stderr)
        commands.append(dict(name=name,command=invocation,exit_code=result.returncode,seconds=time.monotonic()-before))
        write_json(out/'commands.json',commands);print(name,result.returncode,round(commands[-1]['seconds'],3),flush=True)
        if result.returncode!=expected:raise RuntimeError(name+': inspect retained stdout/stderr in '+str(out))
        return result.stdout

    def check(identity,package,label,previous=None,replacement=None,case=None,expected=0):
        values=['component','check','gnu-hello',identity,'--comparison-package',package,'--output',out/label]
        if previous:values+=['--reuse-comparison',out/previous]
        if replacement:values+=['--dependency-package','multibyte-conversion='+str(replacement)]
        if case:values+=['--case',case]
        text=command(label,values,expected);results[label]=load_comparison_result(out/label)
        return results[label],text

    before=time.monotonic();prepare(native,observer,out/'program-prepared')
    preparation_seconds=time.monotonic()-before
    draft=out/'draft';program=out/'program'
    for identity,package,workspace in [('multibyte-conversion',local,draft),('quote-slots',out/'program-prepared',program)]:
        command(identity+'-start',['component','start','gnu-hello',identity,'--comparison-package',package,'--output',workspace])
    command('program-status',['component','status','gnu-hello','quote-slots','--comparison-package',program])
    check('multibyte-conversion',draft,'local-baseline')
    baseline,_=check('quote-slots',program,'program-baseline',replacement=draft)
    assert baseline['status']=='match' and len(baseline['cases'])==12
    neighbor_plan,_=load_comparison_package(neighbor)
    neighbor_identity=neighbor_plan['component_id'];neighbor_case=neighbor_plan['cases'][0]['id']
    check(neighbor_identity,neighbor,'neighbor-baseline',case=neighbor_case)

    source=draft/'source/multibyte.c';original=source.read_text()
    reset='for (uint32_t i=0; i<4; ++i) state->data[i]=0;'
    if reset not in original:reset='for (uint32_t i=0; i<4; ++i) { state->data[i]=0; }'
    assert original.count(reset)==1
    edited=original.replace(reset,'for (uint32_t i=4; i!=0; ) state->data[--i]=0;')
    source.write_text(edited)
    changed,_=check('multibyte-conversion',draft,'local-compatible',previous='local-baseline')
    assert changed['work_counts']['compiler']==1
    consumer,_=check('quote-slots',program,'program-compatible',previous='program-baseline',replacement=draft,case='default')
    assert consumer['work_counts']['compiler']==1
    reused,_=check(neighbor_identity,neighbor,'neighbor-reused',previous='neighbor-baseline',case=neighbor_case)
    assert not any(reused['work_counts'].values())

    store='if (result<UINT32_MAX-1U && output) *output->value=character;'
    assert edited.count(store)==2
    source.write_text(edited.replace(store,'if (result<UINT32_MAX-1U && output) *output->value=character ? 88 : 0;',1))
    try:
        check('multibyte-conversion',draft,'local-wrong',previous='local-compatible',case='context-0-operation-1-chunk-8',expected=2)
        wrong,text=check('quote-slots',program,'program-wrong',previous='program-compatible',replacement=draft,case='default',expected=2)
        assert wrong['cases'][0]['first_difference']['path'].startswith('$.stdout[')
    finally:source.write_text(edited)
    # The printed command replays immutable faulty inputs after draft repair.
    replay=next(line.strip()[len('replay: '):] for line in text.splitlines() if line.strip().startswith('replay: '))
    command('replay',shlex.split(replay)[1:],expected=2)
    results['program-wrong-replay']=load_comparison_result(out/'program-wrong-replay')
    assert results['program-wrong-replay']['cases'][0]['first_difference']==wrong['cases'][0]['first_difference']
    assert results['program-wrong-replay']['work_counts']['compiler']==0
    for identity,package,label,case in [('multibyte-conversion',draft,'local',None),('quote-slots',program,'program','default')]:
        repaired,_=check(identity,package,label+'-repaired',previous=label+'-compatible',
            replacement=draft if label=='program' else None,case=case)
        assert not any(repaired['work_counts'].values())
    command('export',['candidate','export','gnu-hello','--comparison',out/'program-repaired','--output',out/'source-library'])
    before=time.monotonic()
    built=subprocess.run(['make','-C',str(out/'source-library')],capture_output=True,text=True,timeout=60)
    build_seconds=time.monotonic()-before
    (out/'make.stdout').write_text(built.stdout);(out/'make.stderr').write_text(built.stderr)
    if built.returncode:raise RuntimeError('source-library build failed; inspect make.stderr')
    write_json(out/'audit.json',dict(status='pass',seconds=time.monotonic()-started,
        preparation_seconds=preparation_seconds,command_seconds=sum(r['seconds'] for r in commands),
        source_library_build_seconds=build_seconds,commands=len(commands),comparisons=len(results),
        program_baseline_cases=12,program_edit_cases=1,neighbor_cases=1,
        original_startup=True,original_tls_observed=True,wrong_program_replayed_after_repair=True,
        whole_program_portable=False,strong_qualification=False,
        producers={name:sha256_file(Path(__file__).with_name(name)) for name in ('walkthrough.py','comparison.py')},
        observer_sha256=sha256_file(observer),
        results={name:dict(status=r['status'],cases=len(r['cases']),receipt_sha256=r['receipt_sha256'],
            work_counts=r['work_counts'],timings=r['timings']) for name,r in results.items()}))
    print('Normal program component workflow passed',flush=True)


if __name__=='__main__':main()
