"""Extend the retained sprite source project with an executable game-flow consumer."""
import argparse
import importlib.util
import json
from pathlib import Path

from spaghetti_extractor.candidate.source_export_bindings import render_source_service_bridges

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('flow_preparation', HERE/'prepare.py')
preparation = importlib.util.module_from_spec(spec); spec.loader.exec_module(preparation)


def assemble(project, comparison):
    result = json.loads((comparison/'comparison-result.json').read_text())
    if result['status'] != 'match' or result['component_id'] != 'game-flow':
        raise ValueError('requires matching game-flow comparison')
    if not (project/'common/lifecycle-runtime.c').is_file():
        raise ValueError('start from the existing sprite lifecycle source project')
    def write(name, text):
        path = project/name; path.parent.mkdir(parents=True, exist_ok=True)
        if not path.exists() or path.read_text() != text: path.write_text(text)
    rendered = render_source_service_bridges(project/'lifted', bindings={'game-flow': preparation.bridge_spec()})
    write('bridges/game-flow/comparison-service-bridge.h', rendered['game-flow'][0])
    write('bridges/game-flow/bridge.c', preparation.bridge())
    for name in ('flow-state.h', 'flow-runtime.h'): write('common/'+name, (HERE/name).read_text())
    write('common/flow-runtime.c', (HERE/'runtime.c').read_text())
    write('common/lifecycle-runtime.c', (preparation.LIFECYCLE/'runtime.c').read_text())
    write('flow-cases.json', json.dumps([dict(id=row['id'], arguments=row['arguments'],
        expected=row['observations']['original']) for row in result['cases']], indent=2)+'\n')
    write('check-flow.py', '''import argparse,json,subprocess
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--runner',action='append',default=[])
a=p.parse_args();root=Path(__file__).resolve().parent;cases=json.loads((root/'flow-cases.json').read_text())
for case in cases:
    ran=subprocess.run([*a.runner,str(root/'flow'),'source',*case['arguments']],cwd=root,capture_output=True,text=True,timeout=30)
    if ran.returncode:raise RuntimeError(case['id']+': '+ran.stderr[-2000:])
    if json.loads(ran.stdout)!=case['expected']:raise RuntimeError(case['id']+': native observations differ')
print(str(len(cases))+' standalone game-flow cases match original x86 observations')
''')
    marker = '# Game frame/scene consumer\n'
    base = (project/'Makefile').read_text().split(marker)[0]
    objects = 'build/flow-runtime.o build/game-flow.o '+' '.join('build/'+name+'.o' for name in
        ('cleanup-select', 'cleanup-dispose', 'cleanup-clear', 'font-metrics', 'font-render', 'sprite-loader', 'sprite-lifecycle'))
    write('Makefile', base+'\n'+marker+f'''all: flow
flow: {objects} lifted/liblifted.a
\t$(CC) $(LDFLAGS) {objects} lifted/liblifted.a -o $@
build/flow-runtime.o: common/flow-runtime.c
\t@mkdir -p build
\t$(CC) $(CFLAGS) -DDX_STANDALONE -Icommon -MMD -MP -c $< -o $@
build/game-flow.o: bridges/game-flow/bridge.c bridges/game-flow/comparison-service-bridge.h
\t@mkdir -p build
\t$(CC) $(CFLAGS) -Icommon -Ibridges/game-flow -Ilifted/components/game-flow/sources/generated -Ilifted/components/game-flow/sources/source -Ilifted/components/game-flow/sources/headers -MMD -MP -c $< -o $@
''')
    write('README.md', '# DX-Ball connected source consumers\n\n'
        'Build with `make`; run `python check.py`, `python check-drawing.py`, `python check-lifecycle.py` and `python check-flow.py`. '
        'CC/AR select the compiler; check scripts accept --runner for another architecture. '
        'Nine components implement sprite loading, capture/restoration, text/drawing, cleanup and frame/scene control. '
        'Scene and graphics services are controlled: this is a source subsystem project, not the complete game.\n')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('project', 'comparison'): parser.add_argument(name, type=Path)
    args = parser.parse_args(); assemble(args.project.resolve(), args.comparison.resolve())
