"""Define, edit and integrate byte length without changing semantic tool internals."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import time
from spaghetti_extractor.components.comparison_run import load_comparison_result
from spaghetti_extractor.util import write_json
from prepare import prepare


def workflow(base,output):
    if not os.environ.get('WAYLAND_DISPLAY'):raise ValueError('requires spaghetti-headless-wayland')
    output.mkdir(parents=True,exist_ok=False);started=time.monotonic();commands=[]
    prepare(base,output/'prepared')
    draft=output/'draft'
    def command(name,args,want=0):
        tick=time.monotonic()
        result=subprocess.run([sys.executable,'-m','spaghetti_extractor',*map(str,args)],capture_output=True,timeout=600)
        (output/(name+'.stdout')).write_bytes(result.stdout);(output/(name+'.stderr')).write_bytes(result.stderr)
        commands.append(dict(name=name,arguments=list(map(str,args)),exit_code=result.returncode,seconds=time.monotonic()-tick))
        write_json(output/'commands.json',commands)
        assert result.returncode==want,(name,result.returncode,result.stdout[-2000:],result.stderr[-2000:])
    def check(name,package=draft,identity='string-byte-length',reuse=None,case=None,want=0,rerun=False):
        args=['component','check','jq',identity,'--comparison-package',package,'--output',output/name]
        if reuse:args+=['--reuse-comparison',output/reuse]
        if case:args+=['--case',case]
        if rerun:args+=['--rerun']
        command(name,args,want);return load_comparison_result(output/name)
    command('start',['component','start','jq','string-byte-length','--comparison-package',output/'prepared/string-byte-length','--output',draft])
    command('inspect',['component','status','jq','string-byte-length','--comparison-package',draft])
    check('baseline')
    check('neighbor-baseline',package=base,identity='string-length',case='program')
    source=draft/'source/length.c';original=source.read_text()
    edited=original.replace('    int32_t length=',
        '    if (bytes.length==0) { services->release(services->context,value);return 0; }\n    int32_t length=')
    assert edited!=original;source.write_text(edited)
    changed=check('edited',reuse='baseline')
    assert changed['work_counts']['compiler']==1,changed['work_counts']
    neighbor=check('neighbor-reused',package=base,identity='string-length',case='program',reuse='neighbor-baseline')
    assert not any(neighbor['work_counts'].values()),neighbor['work_counts']
    try:
        source.write_text(edited.replace('services->release(services->context,value);','/* missing release */'))
        wrong=check('missing-release',reuse='edited',case='retained',want=2)
    finally:source.write_text(edited)
    command('diagnose',['component','status','jq','string-byte-length','--comparison-result',output/'missing-release'])
    replay=check('replay',package=output/'missing-release/inputs',reuse='missing-release',case='retained',want=2,rerun=True)
    assert replay['cases'][0]['status']==wrong['cases'][0]['status']
    repaired=check('repaired',reuse='edited')
    assert not any(repaired['work_counts'].values()),repaired['work_counts']
    write_json(output/'workflow.json',dict(status='pass',seconds=time.monotonic()-started,
        local_compilers=changed['work_counts']['compiler'],neighbor_zero_work=True,
        missing_release_status=wrong['status'],missing_release_case=wrong['cases'][0]['status'],
        replay_work=replay['work_counts'],new_semantic_tool_internals=False,strong_qualification=False))
    print('component workflow passed')


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('base',type=Path,help='retained pinned string-length comparison workspace')
    parser.add_argument('output',type=Path)
    args=parser.parse_args();workflow(args.base.resolve(),args.output.resolve())
