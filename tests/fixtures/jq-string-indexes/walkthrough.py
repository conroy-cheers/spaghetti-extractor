"""Establish, edit and replay the new search boundary with public commands."""
import argparse
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import time

from prepare import prepare


def workflow(base, output):
    if not os.environ.get('WAYLAND_DISPLAY'):
        raise ValueError('run inside spaghetti-headless-wayland')
    output.mkdir(parents=True,exist_ok=False)
    prepare(base,output/'prepared')
    commands=[];results={}
    def command(name,args,expected=0):
        args=list(map(str,args));start=time.monotonic()
        ran=subprocess.run(args,capture_output=True,text=True,timeout=120)
        (output/(name+'.stdout')).write_text(ran.stdout)
        (output/(name+'.stderr')).write_text(ran.stderr)
        commands.append(dict(name=name,arguments=args,exit_code=ran.returncode,seconds=time.monotonic()-start))
        (output/'commands.json').write_text(json.dumps(commands,indent=2)+'\n')
        print(name,ran.returncode,round(commands[-1]['seconds'],3),flush=True)
        if ran.returncode!=expected:raise RuntimeError(name+': '+ran.stdout+'\n'+ran.stderr)
        return ran.stdout
    cli=[sys.executable,'-m','spaghetti_extractor']
    package=output/'prepared/string-indexes';work=output/'work'
    command('start',[*cli,'component','start','jq','string-indexes','--comparison-package',package,'--output',work])
    command('status',[*cli,'component','status','jq','string-indexes','--comparison-package',work])
    def check(name,previous=None,case=None,expected=0):
        args=[*cli,'component','check','jq','string-indexes','--comparison-package',work,'--output',output/name]
        if previous:args+=['--reuse-comparison',output/previous]
        if case:args+=['--case',case]
        text=command(name,args,expected)
        result=json.loads((output/name/'comparison-result.json').read_text());results[name]=result
        return result,text
    baseline,_=check('baseline')
    source=work/'source/indexes.c';original=source.read_text()
    old='while (matched < pattern.length && text.data[start + matched] == pattern.data[matched])\n                ++matched;'
    new='for (; matched < pattern.length; ++matched) {\n                if (text.data[start + matched] != pattern.data[matched]) break;\n            }'
    if original.count(old)!=1:raise ValueError('review changed local loop before the example edit')
    compatible=original.replace(old,new);source.write_text(compatible)
    edited,_=check('edited','baseline')
    source.write_text(compatible.replace('services->release(services->context, needle);','/* deliberate omitted release */'))
    try:
        wrong,text=check('missing-release','edited','retained',2)
    finally:
        source.write_text(compatible)
    replay=next(line.strip().removeprefix('replay: ') for line in text.splitlines() if line.strip().startswith('replay: '))
    command('replay',shlex.split(replay),2)
    repaired,_=check('repaired','edited')
    command('export',[*cli,'candidate','export','jq','--comparison',output/'repaired','--output',output/'source-library'])
    report=dict(status='pass',command_seconds=sum(r['seconds'] for r in commands),
        results={name:dict(status=r['status'],cases=len(r['cases']),work_counts=r['work_counts'],timings=r['timings'])
                 for name,r in results.items()},
        installed_package=__import__('spaghetti_extractor').__file__,
        new_tool_internals=False,all_wine_headless_wayland=True,pilot_rebuilt=False,
        preparation=json.loads((output/'prepared/preparation.json').read_text()),
        scope='New manual boundary using shared state transport, local edit, lifetime-defect replay and actual native interpreter consumer. Allocation failure remains unobserved.')
    (output/'workflow.json').write_text(json.dumps(report,indent=2)+'\n')
    print('string-indexes public workflow passed',flush=True)


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('base',type=Path);parser.add_argument('output',type=Path)
    args=parser.parse_args();workflow(args.base.resolve(),args.output.resolve())
