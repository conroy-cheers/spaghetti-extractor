"""Assemble checked title animation with the existing portable source consumers."""
import argparse
import importlib.util
import json
from pathlib import Path

from spaghetti_extractor.candidate.source_export_bindings import render_source_service_bridges

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('title_preparation', HERE/'prepare.py')
preparation = importlib.util.module_from_spec(spec); spec.loader.exec_module(preparation)


def assemble(project, comparison):
    result = json.loads((comparison/'comparison-result.json').read_text())
    if result['status'] != 'match' or result['component_id'] != 'title-animation': raise ValueError('requires matching animation comparison')
    if not (project/'common/pcx-runtime.c').is_file(): raise ValueError('start from the PCX source project')
    def write(name, text):
        path = project/name; path.parent.mkdir(parents=True, exist_ok=True)
        if not path.exists() or path.read_text() != text: path.write_text(text)
    rendered = render_source_service_bridges(project/'lifted', bindings={'title-animation': preparation.bridge_spec()})
    write('bridges/title-animation/comparison-service-bridge.h', rendered['title-animation'][0])
    write('bridges/title-animation/bridge.c', preparation.bridge())
    for name in ('title-state.h', 'title-runtime.h', 'title-native.h'): write('common/'+name, (HERE/name).read_text())
    write('common/title-runtime.c', (HERE/'runtime.c').read_text())
    write('title-cases.json', json.dumps([dict(id=row['id'], arguments=row['arguments'],
        expected=row['observations']['original']) for row in result['cases']], indent=2)+'\n')
    write('check-title.py', '''import argparse,json,subprocess
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--runner',action='append',default=[])
a=p.parse_args();root=Path(__file__).resolve().parent;cases=json.loads((root/'title-cases.json').read_text())
for case in cases:
    ran=subprocess.run([*a.runner,str(root/'title'),'source',*case['arguments']],cwd=root,capture_output=True,text=True,timeout=30)
    if ran.returncode:raise RuntimeError(case['id']+': '+ran.stderr[-2000:])
    if json.loads(ran.stdout)!=case['expected']:raise RuntimeError(case['id']+': native observations differ')
print(str(len(cases))+' standalone title animation cases match original x86 observations')
''')
    marker = '# Title animation consumer\n'; base = (project/'Makefile').read_text().split(marker)[0]
    write('Makefile', base+'\n'+marker+'''all: title
title: build/title-runtime.o build/title-animation.o build/cleanup-select.o build/cleanup-dispose.o build/cleanup-clear.o build/font-metrics.o build/font-render.o build/sprite-drawing.o lifted/liblifted.a
\t$(CC) $(LDFLAGS) build/title-runtime.o build/title-animation.o build/cleanup-select.o build/cleanup-dispose.o build/cleanup-clear.o build/font-metrics.o build/font-render.o build/sprite-drawing.o lifted/liblifted.a -o $@
build/title-runtime.o: common/title-runtime.c
\t@mkdir -p build
\t$(CC) $(CFLAGS) -DDX_STANDALONE -Icommon -MMD -MP -c $< -o $@
build/title-animation.o: bridges/title-animation/bridge.c bridges/title-animation/comparison-service-bridge.h
\t@mkdir -p build
\t$(CC) $(CFLAGS) -Icommon -Ibridges/title-animation -Ilifted/components/title-animation/sources/generated -Ilifted/components/title-animation/sources/source -Ilifted/components/title-animation/sources/headers -MMD -MP -c $< -o $@
''')
    write('README.md', '# DX-Ball connected source consumers\n\n'
        'Build with `make`; run `python check.py`, `python check-drawing.py`, `python check-lifecycle.py`, '
        '`python check-flow.py`, `python check-pcx.py` and `python check-title.py`. '
        'CC/AR select the compiler; check scripts accept --runner for another architecture. '
        'Eleven components implement sprite loading, capture/restoration, text/drawing, cleanup, frame/scene control, '
        'PCX image/palette loading and title animation. '
        'Platform services and other scene bodies remain outside this subsystem source project.\n')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('project', 'comparison'): parser.add_argument(name, type=Path)
    args = parser.parse_args(); assemble(args.project.resolve(), args.comparison.resolve())
