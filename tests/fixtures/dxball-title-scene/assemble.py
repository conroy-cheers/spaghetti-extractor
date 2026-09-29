"""Add the checked scene to the existing portable source project."""
import argparse
import importlib.util
import json
from pathlib import Path

from spaghetti_extractor.candidate.source_export_bindings import render_source_service_bridges

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('scene_preparation', HERE/'prepare.py')
preparation = importlib.util.module_from_spec(spec); spec.loader.exec_module(preparation)


def assemble(project, comparison):
    result = json.loads((comparison/'comparison-result.json').read_text())
    if result['status'] != 'match' or result['component_id'] != 'title-scene': raise ValueError('requires matching scene comparison')
    if not (project/'common/title-runtime.c').is_file(): raise ValueError('start from the title animation source project')
    def write(name, text):
        path = project/name; path.parent.mkdir(parents=True, exist_ok=True)
        if not path.exists() or path.read_text() != text: path.write_text(text)
    rendered = render_source_service_bridges(project/'lifted', bindings={'title-scene':preparation.bridge_spec()})
    write('bridges/title-scene/comparison-service-bridge.h', rendered['title-scene'][0])
    write('bridges/title-scene/bridge.c', preparation.bridge())
    write('common/scene-runtime.h', preparation.runtime_header())
    write('common/scene-state.h', (HERE/'scene-state.h').read_text())
    write('common/scene-runtime.c', (HERE/'runtime.c').read_text())
    write('common/title-runtime.c', (preparation.TITLE/'runtime.c').read_text())
    write('scene-cases.json', json.dumps([dict(id=row['id'],arguments=row['arguments'],
        expected=row['observations']['original']) for row in result['cases']],indent=2)+'\n')
    write('check-scene.py', '''import argparse,json,subprocess
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--runner',action='append',default=[])
a=p.parse_args();root=Path(__file__).resolve().parent;cases=json.loads((root/'scene-cases.json').read_text())
for case in cases:
    ran=subprocess.run([*a.runner,str(root/'scene'),'source',*case['arguments']],cwd=root,capture_output=True,text=True,timeout=30)
    if ran.returncode:raise RuntimeError(case['id']+': '+ran.stderr[-2000:])
    if json.loads(ran.stdout)!=case['expected']:raise RuntimeError(case['id']+': native observations differ')
print(str(len(cases))+' standalone title scene cases match original x86 observations')
''')
    marker = '# Title scene consumer\n'; base = (project/'Makefile').read_text().split(marker)[0]
    write('Makefile',base+'\n'+marker+'''all: scene
scene: build/scene-runtime.o build/title-scene.o build/title-animation.o build/cleanup-select.o build/cleanup-dispose.o build/cleanup-clear.o build/font-metrics.o build/font-render.o build/sprite-drawing.o lifted/liblifted.a
\t$(CC) $(LDFLAGS) build/scene-runtime.o build/title-scene.o build/title-animation.o build/cleanup-select.o build/cleanup-dispose.o build/cleanup-clear.o build/font-metrics.o build/font-render.o build/sprite-drawing.o lifted/liblifted.a -o $@
build/scene-runtime.o: common/scene-runtime.c
\t@mkdir -p build
\t$(CC) $(CFLAGS) -DDX_STANDALONE -Icommon -MMD -MP -c $< -o $@
build/title-scene.o: bridges/title-scene/bridge.c bridges/title-scene/comparison-service-bridge.h
\t@mkdir -p build
\t$(CC) $(CFLAGS) -Icommon -Ibridges/title-scene -Ilifted/components/title-scene/sources/generated -Ilifted/components/title-scene/sources/source -Ilifted/components/title-scene/sources/headers -MMD -MP -c $< -o $@
''')
    write('README.md','# DX-Ball connected source consumers\n\n'
        'Build with `make`; run `python check.py`, `python check-drawing.py`, `python check-lifecycle.py`, '
        '`python check-flow.py`, `python check-pcx.py`, `python check-title.py` and `python check-scene.py`. '
        'CC/AR select the compiler; check scripts accept --runner for another architecture. '
        'Twelve components implement sprite loading, capture/restoration, text/drawing, cleanup, frame/scene control, '
        'PCX image/palette loading, title animation and title scene orchestration. '
        'Platform backends and remaining scene/gameplay bodies still require lifting.\n')


if __name__ == '__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('project','comparison'): parser.add_argument(name,type=Path)
    args=parser.parse_args(); assemble(args.project.resolve(),args.comparison.resolve())
