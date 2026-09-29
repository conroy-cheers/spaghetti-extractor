"""Public fresh setup, workspace inspection, C edits, native consumers and replay."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import time
from spaghetti_extractor.components.comparison_run import load_comparison_result
from spaghetti_extractor.util import write_json,sha256_file
from prepare import prepare


def workflow(base,output):
    if not os.environ.get('WAYLAND_DISPLAY'):raise ValueError('requires spaghetti-headless-wayland')
    root=output.resolve();root.mkdir(parents=True,exist_ok=False);draft=root/'length-draft';commands=[];started=time.monotonic()
    prepare(base,root/'prepared')
    def command(name,args,want=0):
     start=time.monotonic();p=subprocess.run([sys.executable,'-m','spaghetti_extractor',*map(str,args)],capture_output=True,env=os.environ,timeout=600)
     (root/(name+'.stdout')).write_bytes(p.stdout);(root/(name+'.stderr')).write_bytes(p.stderr)
     commands.append(dict(name=name,arguments=list(map(str,args)),exit_code=p.returncode,seconds=time.monotonic()-start))
     write_json(root/'commands.json',commands)
     assert p.returncode==want,(name,p.returncode,p.stdout[-1800:],p.stderr[-1800:])
     return p

    def check(identity,package,name,reuse=None,case=None,want=0):
     args=['component','check','jq',identity,'--comparison-package',package,'--output',root/name]
     if reuse:args+=['--reuse-comparison',root/reuse]
     if case:args+=['--case',case]
     command(name,args,want);return load_comparison_result(root/name)
    command('start',['component','start','jq','string-length','--comparison-package',root/'prepared/string-length','--output',draft])
    command('inspect',['component','status','jq','string-length','--comparison-package',draft,'--json'])
    view=json.loads((root/'inspect.stdout').read_text());assert view['assurance']=='not-evaluated'
    assert len(view['units'][0]['service_catalog']['contracts'])==2
    check('string-length',draft,'local-baseline')
    neighbor=base.resolve()
    check('string-slice',neighbor,'neighbor-baseline')
    source=draft/'source/length.c';original=source.read_text()
    needle='if ((bytes.data[offset+i]&0xc0U)!=0x80U) { step=i;break; }'
    assert original.count(needle)==1
    compatible=original.replace(needle,'if (bytes.data[offset+i]<0x80U || bytes.data[offset+i]>=0xc0U) { step=i;break; }')
    source.write_text(compatible)
    r=check('string-length',draft,'local-edit','local-baseline');assert r['work_counts']['compiler']==1
    r=check('string-slice',neighbor,'neighbor-reused','neighbor-baseline');assert not any(r['work_counts'].values()),r['work_counts']
    try:
     source.write_text(compatible.replace('if (width>bytes.length-offset) step=bytes.length-offset;', 'if (width>bytes.length-offset) step=1;'))
     r=check('string-length',draft,'wrong-truncation','local-edit','retained',2);assert r['status']=='mismatch'
    finally:source.write_text(compatible)
    r=check('string-length',root/'wrong-truncation/inputs','truncation-replay',case='retained',want=2)
    assert r['cases'][0]['first_difference']==load_comparison_result(root/'wrong-truncation')['cases'][0]['first_difference']
    try:
     source.write_text(compatible.replace('++count;', 'count+=step;'))
     r=check('string-length',draft,'wrong-program','local-edit','program',2);assert r['status']=='mismatch'
    finally:source.write_text(compatible)
    r=check('string-length',root/'wrong-program/inputs','program-replay',case='program',want=2)
    assert r['cases'][0]['first_difference']==load_comparison_result(root/'wrong-program')['cases'][0]['first_difference']
    r=check('string-length',draft,'local-repaired','local-edit');assert not any(r['work_counts'].values())
    write_json(root/'local-workflow.json',dict(status='pass',seconds=time.monotonic()-started,commands_sha256=sha256_file(root/'commands.json'),producer_sha256=sha256_file(Path(__file__)),
     neighbor_zero_work=True,local_compilers=1,malformed_and_consumer_defects_replayed=True,strong_qualification=False,overall_goal_complete=False))
    print('local workflow pass',flush=True)


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('base',type=Path);p.add_argument('output',type=Path)
    a=p.parse_args();workflow(a.base.resolve(),a.output.resolve())
