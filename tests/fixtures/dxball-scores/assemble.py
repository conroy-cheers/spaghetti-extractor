"""Add the checked score table to the existing portable source project."""
import argparse
import importlib.util
import json
from pathlib import Path
import shutil

from spaghetti_extractor.candidate.source_export_bindings import render_source_service_bridges

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('scores_preparation',HERE/'prepare.py')
preparation=importlib.util.module_from_spec(spec);spec.loader.exec_module(preparation)


def assemble(project,comparison):
    result=json.loads((comparison/'comparison-result.json').read_text())
    if result['status']!='match' or result['component_id']!='score-table':raise ValueError('requires matching score comparison')
    if not (project/'check-menu.py').is_file():raise ValueError('start from the menu source project')
    def write(name,text):
        path=project/name;path.parent.mkdir(parents=True,exist_ok=True)
        if not path.exists() or path.read_text()!=text:path.write_text(text)
    rendered=render_source_service_bridges(project/'lifted',bindings={'score-table':preparation.bridge_spec()})
    write('bridges/score-table/comparison-service-bridge.h',rendered['score-table'][0])
    write('bridges/score-table/bridge.c',preparation.bridge())
    write('common/scores-runtime.h',preparation.runtime_header())
    write('common/scores-state.h',(HERE/'scores-state.h').read_text())
    write('common/scores-runtime.c',(HERE/'runtime.c').read_text())
    shutil.copyfile(comparison/'inputs/runtime/score.dat',project/'score.dat')
    write('scores-cases.json',json.dumps([dict(id=row['id'],arguments=row['arguments'],
        expected=row['observations']['original']) for row in result['cases']],indent=2)+'\n')
    write('check-scores.py','''import argparse,json,subprocess
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--runner',action='append',default=[])
a=p.parse_args();root=Path(__file__).resolve().parent;cases=json.loads((root/'scores-cases.json').read_text())
for case in cases:
    ran=subprocess.run([*a.runner,str(root/'scores'),'source',*case['arguments']],cwd=root,capture_output=True,text=True,timeout=30)
    if ran.returncode:raise RuntimeError(case['id']+': '+ran.stderr[-2000:])
    if json.loads(ran.stdout)!=case['expected']:raise RuntimeError(case['id']+': native observations differ')
print(str(len(cases))+' standalone score-table cases match original x86 observations')
''')
    marker='# Score table consumer\n';base=(project/'Makefile').read_text().split(marker)[0]
    write('Makefile',base+'\n'+marker+'''all: scores
scores: build/scores-runtime.o build/score-table.o lifted/liblifted.a
\t$(CC) $(LDFLAGS) build/scores-runtime.o build/score-table.o lifted/liblifted.a -o $@
build/scores-runtime.o: common/scores-runtime.c
\t@mkdir -p build
\t$(CC) $(CFLAGS) -DDX_STANDALONE -Icommon -MMD -MP -c $< -o $@
build/score-table.o: bridges/score-table/bridge.c bridges/score-table/comparison-service-bridge.h
\t@mkdir -p build
\t$(CC) $(CFLAGS) -Icommon -Ibridges/score-table -Ilifted/components/score-table/sources/generated -Ilifted/components/score-table/sources/source -Ilifted/components/score-table/sources/headers -MMD -MP -c $< -o $@
''')
    write('README.md','# DX-Ball connected source consumers\n\n'
        'Build with `make`; run `python check.py`, `python check-drawing.py`, `python check-lifecycle.py`, '
        '`python check-flow.py`, `python check-pcx.py`, `python check-title.py`, `python check-scene.py`, '
        '`python check-menu.py` and `python check-scores.py`. '
        'CC/AR select compilers; check scripts accept --runner for another architecture. '
        'Fourteen components implement sprite loading, capture/restoration, text/drawing, cleanup, frame/scene control, '
        'PCX image/palette loading, title/menu orchestration and animation, and the persistent score table. '
        'Platform backends and remaining scene/gameplay bodies still require lifting.\n')


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('project','comparison'):p.add_argument(name,type=Path)
    a=p.parse_args();assemble(a.project.resolve(),a.comparison.resolve())
