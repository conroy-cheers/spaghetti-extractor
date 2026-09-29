"""Edit one independent component and exercise it through the public program loop."""
import argparse
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import time

from spaghetti_extractor.components.comparison_package import load_comparison_package
from spaghetti_extractor.components.comparison_run import load_comparison_result
from spaghetti_extractor.util import sha256_file, write_json


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    names=('package','program_package','neighbor_package','output')
    for name in names:parser.add_argument(name,type=Path)
    args=parser.parse_args()
    if not os.environ.get('WAYLAND_DISPLAY'):raise ValueError('run inside spaghetti-headless-wayland')
    package,program,neighbor,out=[getattr(args,name).resolve() for name in names]
    out.mkdir(parents=True,exist_ok=False);started=time.monotonic();commands=[];results={}
    local_case='context-0-transport-1'

    def command(label,arguments,expected=0):
        invocation=[sys.executable,'-m','spaghetti_extractor',*map(str,arguments)];before=time.monotonic()
        completed=subprocess.run(invocation,capture_output=True,text=True,timeout=180)
        (out/(label+'.stdout')).write_text(completed.stdout);(out/(label+'.stderr')).write_text(completed.stderr)
        commands.append(dict(name=label,command=invocation,exit_code=completed.returncode,seconds=time.monotonic()-before))
        write_json(out/'commands.json',commands);print(label,completed.returncode,round(commands[-1]['seconds'],3),flush=True)
        if completed.returncode!=expected:raise RuntimeError(label+': inspect retained logs in '+str(out))
        return completed.stdout

    def check(identity,inputs,label,case,previous=None,replacement=None,expected=0):
        arguments=['component','check','gnu-hello',identity,'--comparison-package',inputs,
            '--case',case,'--output',out/label]
        if previous:arguments+=['--reuse-comparison',out/previous]
        if replacement:arguments+=['--dependency-package','string-conversion='+str(replacement)]
        text=command(label,arguments,expected);results[label]=load_comparison_result(out/label)
        return results[label],text

    draft=out/'draft'
    command('start',['component','start','gnu-hello','string-conversion','--comparison-package',package,'--output',draft])
    command('program-status',['component','status','gnu-hello','quote-slots','--comparison-package',program])
    check('string-conversion',draft,'local-baseline',local_case)
    baseline,_=check('quote-slots',program,'program-baseline','default',replacement=draft)
    assert baseline['status']=='match'
    selected,_=load_comparison_package(out/'program-baseline/inputs')
    assert selected['composition']['program_entries']==['quote-slots','string-conversion']
    assert selected['composition']['nodes']['string-conversion']['required_by']==[]
    for side,calls in [('original',0),('source',1)]:
        report=json.loads((out/f'program-baseline/cases/0000-{side}.report.json').read_text())
        assert report['diagnostics']['string_calls']==calls
    neighbor_plan,_=load_comparison_package(neighbor)
    neighbor_id=neighbor_plan['component_id'];neighbor_case=neighbor_plan['cases'][0]['id']
    check(neighbor_id,neighbor,'neighbor-baseline',neighbor_case)

    source=draft/'source/string.c';original=source.read_text()
    copy='for (uint32_t i=0; i<4; ++i) saved[i] = state->data[i];'
    assert original.count(copy)==1
    compatible=original.replace(copy,'for (uint32_t i=4; i!=0; ) { --i; saved[i] = state->data[i]; }')
    source.write_text(compatible)
    changed,_=check('string-conversion',draft,'local-compatible',local_case,previous='local-baseline')
    assert changed['work_counts']['compiler']==1
    integrated,_=check('quote-slots',program,'program-compatible','default',previous='program-baseline',replacement=draft)
    assert integrated['work_counts']['compiler']==1
    assert integrated['selection_impact']['program_integration_affected']
    reused,_=check(neighbor_id,neighbor,'neighbor-reused',neighbor_case,previous='neighbor-baseline')
    assert not any(reused['work_counts'].values())

    clear='if (output) *input->value = 0;'
    assert compatible.count(clear)==1
    source.write_text(compatible.replace(clear,'if (output) { *input->value = 0; if (count) output->value[0] = 88; }'))
    try:
        check('string-conversion',draft,'local-wrong',local_case,previous='local-compatible',expected=2)
        wrong,text=check('quote-slots',program,'program-wrong','default',previous='program-compatible',replacement=draft,expected=2)
        assert wrong['cases'][0]['first_difference']['path']=='$.stdout[0]'
    finally:source.write_text(compatible)
    replay=next(line.strip()[len('replay: '):] for line in text.splitlines() if line.strip().startswith('replay: '))
    command('replay',shlex.split(replay)[1:],expected=2)
    replayed=load_comparison_result(out/'program-wrong-replay');results['program-wrong-replay']=replayed
    assert replayed['cases'][0]['first_difference']==wrong['cases'][0]['first_difference']
    assert replayed['work_counts']['compiler']==0
    for identity,inputs,label,case,replacement in [('string-conversion',draft,'local',local_case,None),
            ('quote-slots',program,'program','default',draft)]:
        repaired,_=check(identity,inputs,label+'-repaired',case,previous=label+'-compatible',replacement=replacement)
        assert not any(repaired['work_counts'].values())
    command('export',['candidate','export','gnu-hello','--comparison',out/'program-repaired','--output',out/'source-library'])
    before=time.monotonic()
    built=subprocess.run(['make','-C',str(out/'source-library')],capture_output=True,text=True,timeout=60)
    (out/'make.stdout').write_text(built.stdout);(out/'make.stderr').write_text(built.stderr)
    if built.returncode:raise RuntimeError('source build failed; inspect make.stderr')
    write_json(out/'audit.json',dict(status='pass',seconds=time.monotonic()-started,
        commands=len(commands),command_seconds=sum(row['seconds'] for row in commands),
        source_build_seconds=time.monotonic()-before,local_cases=1,program_cases=1,neighbor_cases=1,
        public_program_comparison=True,program_entries=selected['composition']['program_entries'],
        whole_program_portable=False,strong_qualification=False,replay_after_repair=True,
        producer_sha256=sha256_file(Path(__file__)),
        results={name:dict(status=row['status'],receipt_sha256=row['receipt_sha256'],
            work_counts=row['work_counts'],timings=row['timings']) for name,row in results.items()}))
    print('Independent program component workflow passed',flush=True)


if __name__=='__main__':main()
