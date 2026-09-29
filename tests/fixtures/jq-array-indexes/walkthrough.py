"""Public new-boundary, edit/diagnose/reuse and connected-consumer handoff."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import time

from prepare import prepare
from connect import connect


def workflow(network,output):
    if not os.environ.get('WAYLAND_DISPLAY'):
        raise ValueError('run inside spaghetti-headless-wayland')
    output.mkdir(parents=True,exist_ok=False);started=time.monotonic()
    commands=[];checks={};cli=[sys.executable,'-m','spaghetti_extractor']
    def command(name,args,expected=0):
        args=list(map(str,args));start=time.monotonic()
        ran=subprocess.run(args,capture_output=True,text=True,timeout=180)
        (output/(name+'.stdout')).write_text(ran.stdout);(output/(name+'.stderr')).write_text(ran.stderr)
        commands.append(dict(name=name,argv=args,exit_code=ran.returncode,seconds=time.monotonic()-start))
        (output/'commands.json').write_text(json.dumps(commands,indent=2)+'\n')
        print(name,ran.returncode,round(commands[-1]['seconds'],3),flush=True)
        if ran.returncode!=expected:raise RuntimeError(name+'\n'+ran.stdout+'\n'+ran.stderr)
        return ran.stdout
    def check(name,unit,work,previous=None,case=None,expected=0,extra=()):
        args=[*cli,'component','check','jq',unit,'--comparison-package',work,'--output',output/name,*extra]
        if previous:args+=['--reuse-comparison',output/previous]
        if case:args+=['--case',case]
        text=command(name,args,expected)
        result=json.loads((output/name/'comparison-result.json').read_text())
        compilation=json.loads((output/name/'build/compilation.json').read_text())
        reused=not any(result['work_counts'].values())
        checks[name]=dict(status=result['status'],work_counts=result['work_counts'],timings=result['timings'],
            compiled=result['work_counts']['compiler'],reused=len(compilation['units']) if reused else sum(u['reused'] for u in compilation['units']))
        return text
    prepare(network,output/'prepared')
    work=output/'local'
    command('open',[*cli,'component','start','jq','array-indexes','--comparison-package',output/'prepared/array-indexes','--output',work])
    command('inspect',[*cli,'component','status','jq','array-indexes','--comparison-package',work])
    check('baseline','array-indexes',work)
    source=work/'source/indexes.c';original=source.read_text()
    old='if (!s->equal(e, actual, expected)) match = -1;'
    new='uint32_t same = s->equal(e, actual, expected);\n            if (!same) match = -1;'
    if original.count(old)!=1:raise ValueError('review changed loop before the local edit')
    edited=original.replace(old,new);source.write_text(edited)
    check('edited','array-indexes',work,'baseline')
    source.write_text(edited.replace('s->release(e, needle);','/* deliberately omitted release */'))
    try:
        feedback=check('missing-release','array-indexes',work,'edited','retained',2)
    finally:
        source.write_text(edited)
    replay=next(line.strip().removeprefix('replay: ') for line in feedback.splitlines() if line.strip().startswith('replay: '))
    command('replay',shlex.split(replay),2)
    check('repaired','array-indexes',work,'edited')
    connect(network,work,output/'connected')
    getter=output/'getter'
    command('open-getter',[*cli,'component','start','jq','value-get','--comparison-package',output/'connected/value-get','--output',getter])
    check('getter-check','value-get',getter)
    selection=output/'network'
    command('refine-network',[*cli,'component','start','jq','path-set','--comparison-package',network,
        '--refine-requirement',f'path-get/get={getter}','--refine-requirement',f'path-set/get={getter}','--output',selection])
    # One existing driver-supported interpreter context exercises both lifted
    # paths and the new search; no synthetic caller edges are introduced.
    arguments=['[.items[[1,2]],getpath(["items",[1,2]])]','{"items":[1,2,1,2,3]}','null','program']
    check('network-check','path-set',selection,case='program-array-indexes',
        extra=['--case-arguments',json.dumps(arguments)])
    source.write_text(edited.replace('uint32_t same =','const uint32_t same ='))
    check('local-followup','array-indexes',work,'repaired','retained')
    check('network-followup','path-set',selection,'network-check','program-array-indexes',
        extra=['--case-arguments',json.dumps(arguments),'--dependency-source',f'array-indexes={work}'])
    command('export',[*cli,'candidate','export','jq','--comparison',output/'network-followup','--output',output/'source-library'])
    report=dict(status='pass',seconds=time.monotonic()-started,commands=commands,checks=checks,
        installed_package=__import__('spaghetti_extractor').__file__,
        tooling_gap_discovered='The initial connected handoff required shared refinement support for a newly declared transitive supplier.',
        source_sha256=hashlib.sha256(source.read_bytes()).hexdigest(),
        preparation=json.loads((output/'prepared/preparation.json').read_text()),
        scope='New array-search boundary, local retained/aliased/empty-pattern/interpreter cases, lifetime defect replay and selected value/path consumers. All Wine uses headless Wayland. No pilot or solver work; native equality/append and other lower services remain.')
    (output/'workflow.json').write_text(json.dumps(report,indent=2)+'\n')
    print('array-indexes handoff passed',flush=True)


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('network',type=Path);parser.add_argument('output',type=Path)
    args=parser.parse_args();workflow(args.network.resolve(),args.output.resolve())
