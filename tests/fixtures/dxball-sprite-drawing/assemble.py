"""Add the drawing consumer to the existing exported asset/font source project."""
import argparse
import json
from pathlib import Path

from spaghetti_extractor.candidate.source_export_bindings import render_source_service_bridges
from prepare import HERE, bridge, bridge_spec


def assemble(project,comparison):
    result=json.loads((comparison/'comparison-result.json').read_text())
    if result['status']!='match' or result['component_id']!='sprite-drawing':
        raise ValueError('requires matching sprite-drawing comparison')
    if not (project/'common/asset-runtime.c').is_file():
        raise ValueError('start from the existing connected asset/font consumer')
    def write(name,text):
        p=project/name;p.parent.mkdir(parents=True,exist_ok=True)
        if not p.exists() or p.read_text()!=text:p.write_text(text)
    generated=render_source_service_bridges(project/'lifted',bindings={'sprite-drawing':bridge_spec()})
    write('bridges/sprite-drawing/comparison-service-bridge.h',generated['sprite-drawing'][0])
    write('bridges/sprite-drawing/bridge.c',bridge())
    write('common/drawing-runtime.c',(HERE/'runtime.c').read_text())
    write('common/drawing-runtime.h',(HERE/'drawing-runtime.h').read_text())
    write('drawing-cases.json',json.dumps([dict(id=row['id'],arguments=row['arguments'],expected=row['observations']['original'])
                                         for row in result['cases']],indent=2)+'\n')
    write('check-drawing.py','''import argparse,json,subprocess
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--runner',action='append',default=[])
a=p.parse_args();root=Path(__file__).resolve().parent;cases=json.loads((root/'drawing-cases.json').read_text())
for case in cases:
    ran=subprocess.run([*a.runner,str(root/'drawing'),'source',*case['arguments']],cwd=root,capture_output=True,text=True,timeout=30)
    if ran.returncode:raise RuntimeError(case['id']+': '+ran.stderr[-2000:])
    if json.loads(ran.stdout)!=case['expected']:raise RuntimeError(case['id']+': native observations differ')
print(str(len(cases))+' standalone drawing cases match original x86 observations')
''')
    marker='# Sprite drawing consumer\n'
    base=(project/'Makefile').read_text().split(marker)[0]
    objects='build/drawing-runtime.o build/sprite-drawing.o '+ ' '.join('build/'+name+'.o' for name in
        ('cleanup-select','cleanup-dispose','cleanup-clear','font-metrics','font-render'))
    write('Makefile',base+'\n'+marker+f'''all: drawing
drawing: {objects} lifted/liblifted.a
\t$(CC) $(LDFLAGS) {objects} lifted/liblifted.a -o $@
build/drawing-runtime.o: common/drawing-runtime.c
\t@mkdir -p build
\t$(CC) $(CFLAGS) -DDX_STANDALONE -Icommon -MMD -MP -c $< -o $@
build/sprite-drawing.o: bridges/sprite-drawing/bridge.c bridges/sprite-drawing/comparison-service-bridge.h
\t@mkdir -p build
\t$(CC) $(CFLAGS) -Icommon -Ibridges/sprite-drawing -Ilifted/components/sprite-drawing/sources/generated -Ilifted/components/sprite-drawing/sources/source -Ilifted/components/sprite-drawing/sources/headers -MMD -MP -c $< -o $@
''')
    write('README.md','# DX-Ball connected sprite source consumer\n\n'
        'Run `make`, `python check.py` (assets/font/cleanup) and `python check-drawing.py`. '
        'CC/AR select the compiler; both check scripts accept --runner for another architecture. '
        'Seven components implement loading, metrics, text/sprite drawing and cleanup. '
        'Graphics services are controlled; this is a subsystem consumer, not the complete game.\n')


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('project',type=Path);p.add_argument('comparison',type=Path)
    a=p.parse_args();assemble(a.project.resolve(),a.comparison.resolve())
