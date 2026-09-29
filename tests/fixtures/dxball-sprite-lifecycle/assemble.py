"""Extend the retained portable asset/drawing project with capture/restoration."""
import argparse
import importlib.util
import json
from pathlib import Path

from spaghetti_extractor.candidate.source_export_bindings import render_source_service_bridges

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('lifecycle_preparation', HERE/'prepare.py')
preparation = importlib.util.module_from_spec(spec); spec.loader.exec_module(preparation)


def assemble(project, comparison):
    result = json.loads((comparison/'comparison-result.json').read_text())
    if result['status'] != 'match' or result['component_id'] != 'sprite-lifecycle':
        raise ValueError('requires matching sprite lifecycle comparison')
    if not (project/'common/drawing-runtime.c').is_file():
        raise ValueError('start from the existing asset/font/drawing source project')
    def write(name, text):
        path = project/name; path.parent.mkdir(parents=True, exist_ok=True)
        if not path.exists() or path.read_text() != text: path.write_text(text)
    rendered = render_source_service_bridges(project/'lifted', bindings={'sprite-lifecycle': preparation.bridge_spec()})
    write('bridges/sprite-lifecycle/comparison-service-bridge.h', rendered['sprite-lifecycle'][0])
    write('bridges/sprite-lifecycle/bridge.c', preparation.bridge())
    write('common/asset-runtime.c', (preparation.FONT/'asset-runtime.c').read_text())
    write('common/lifecycle-runtime.c', (HERE/'runtime.c').read_text())
    write('common/lifecycle-runtime.h', (HERE/'lifecycle-runtime.h').read_text())
    write('lifecycle-cases.json', json.dumps([dict(id=row['id'], arguments=row['arguments'],
        expected=row['observations']['original']) for row in result['cases']], indent=2)+'\n')
    write('check-lifecycle.py', '''import argparse,json,subprocess
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--runner',action='append',default=[])
a=p.parse_args();root=Path(__file__).resolve().parent;cases=json.loads((root/'lifecycle-cases.json').read_text())
for case in cases:
    ran=subprocess.run([*a.runner,str(root/'lifecycle'),'source',*case['arguments']],cwd=root,capture_output=True,text=True,timeout=30)
    if ran.returncode:raise RuntimeError(case['id']+': '+ran.stderr[-2000:])
    if json.loads(ran.stdout)!=case['expected']:raise RuntimeError(case['id']+': native observations differ')
print(str(len(cases))+' standalone lifecycle cases match original x86 observations')
''')
    marker = '# Sprite capture/restoration consumer\n'
    base = (project/'Makefile').read_text().split(marker)[0]
    objects = 'build/lifecycle-runtime.o build/sprite-lifecycle.o '+' '.join('build/'+name+'.o' for name in
        ('cleanup-select', 'cleanup-dispose', 'cleanup-clear', 'font-metrics', 'font-render', 'sprite-loader'))
    write('Makefile', base+'\n'+marker+f'''all: lifecycle
lifecycle: {objects} lifted/liblifted.a
\t$(CC) $(LDFLAGS) {objects} lifted/liblifted.a -o $@
build/lifecycle-runtime.o: common/lifecycle-runtime.c
\t@mkdir -p build
\t$(CC) $(CFLAGS) -DDX_STANDALONE -Icommon -MMD -MP -c $< -o $@
build/sprite-lifecycle.o: bridges/sprite-lifecycle/bridge.c bridges/sprite-lifecycle/comparison-service-bridge.h
\t@mkdir -p build
\t$(CC) $(CFLAGS) -Icommon -Ibridges/sprite-lifecycle -Ilifted/components/sprite-lifecycle/sources/generated -Ilifted/components/sprite-lifecycle/sources/source -Ilifted/components/sprite-lifecycle/sources/headers -MMD -MP -c $< -o $@
''')
    write('README.md', '# DX-Ball connected sprite source consumers\n\n'
        'Build with `make`; run `python check.py`, `python check-drawing.py` and `python check-lifecycle.py`. '
        'CC/AR select the compiler; check scripts accept --runner for another architecture. '
        'Eight components implement loading, capture/restoration, text/sprite drawing and cleanup. '
        'Graphics services are controlled: this is a subsystem source project, not the complete game.\n')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('project', 'comparison'): parser.add_argument(name, type=Path)
    args = parser.parse_args(); assemble(args.project.resolve(), args.comparison.resolve())
