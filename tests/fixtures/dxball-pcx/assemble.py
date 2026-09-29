"""Add the checked PCX component to the existing portable DX-Ball source project."""
import argparse
import importlib.util
import json
from pathlib import Path
import shutil

from spaghetti_extractor.candidate.source_export_bindings import render_source_service_bridges

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('pcx_preparation', HERE/'prepare.py')
preparation = importlib.util.module_from_spec(spec); spec.loader.exec_module(preparation)


def assemble(project, comparison):
    result = json.loads((comparison/'comparison-result.json').read_text())
    if result['status'] != 'match' or result['component_id'] != 'pcx-image': raise ValueError('requires matching PCX comparison')
    if not (project/'common/flow-runtime.c').is_file(): raise ValueError('start from the game-flow source project')
    def write(name, text):
        path = project/name; path.parent.mkdir(parents=True, exist_ok=True)
        if not path.exists() or path.read_text() != text: path.write_text(text)
    rendered = render_source_service_bridges(project/'lifted', bindings={'pcx-image': preparation.bridge_spec()})
    write('bridges/pcx-image/comparison-service-bridge.h', rendered['pcx-image'][0])
    write('bridges/pcx-image/bridge.c', preparation.bridge())
    for name in ('pcx-state.h', 'pcx-runtime.h'): write('common/'+name, (HERE/name).read_text())
    write('common/pcx-runtime.c', (HERE/'runtime.c').read_text())
    for path in (comparison/'inputs/runtime').glob('*.pcx'): shutil.copyfile(path, project/path.name)
    write('pcx-cases.json', json.dumps([dict(id=row['id'], arguments=row['arguments'],
        expected=row['observations']['original']) for row in result['cases']], indent=2)+'\n')
    write('check-pcx.py', '''import argparse,json,subprocess
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--runner',action='append',default=[])
a=p.parse_args();root=Path(__file__).resolve().parent;cases=json.loads((root/'pcx-cases.json').read_text())
for case in cases:
    ran=subprocess.run([*a.runner,str(root/'pcx'),'source',*case['arguments']],cwd=root,capture_output=True,text=True,timeout=30)
    if ran.returncode:raise RuntimeError(case['id']+': '+ran.stderr[-2000:])
    if json.loads(ran.stdout)!=case['expected']:raise RuntimeError(case['id']+': native observations differ')
print(str(len(cases))+' standalone PCX cases match original x86 observations')
''')
    marker = '# PCX image consumer\n'; base = (project/'Makefile').read_text().split(marker)[0]
    write('Makefile', base+'\n'+marker+'''all: pcx
pcx: build/pcx-runtime.o build/pcx-image.o lifted/liblifted.a
\t$(CC) $(LDFLAGS) build/pcx-runtime.o build/pcx-image.o lifted/liblifted.a -o $@
build/pcx-runtime.o: common/pcx-runtime.c
\t@mkdir -p build
\t$(CC) $(CFLAGS) -DDX_STANDALONE -Icommon -MMD -MP -c $< -o $@
build/pcx-image.o: bridges/pcx-image/bridge.c bridges/pcx-image/comparison-service-bridge.h
\t@mkdir -p build
\t$(CC) $(CFLAGS) -Icommon -Ibridges/pcx-image -Ilifted/components/pcx-image/sources/generated -Ilifted/components/pcx-image/sources/source -Ilifted/components/pcx-image/sources/headers -MMD -MP -c $< -o $@
''')
    write('README.md', '# DX-Ball connected source consumers\n\n'
        'Build with `make`; run `python check.py`, `python check-drawing.py`, `python check-lifecycle.py`, `python check-flow.py` and `python check-pcx.py`. '
        'CC/AR select the compiler; check scripts accept --runner for another architecture. '
        'Ten components implement sprite loading, capture/restoration, text/drawing, cleanup, frame/scene control and PCX image/palette loading. '
        'Scene and graphics services are controlled: this is a source subsystem project, not the complete game.\n')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('project', 'comparison'): parser.add_argument(name, type=Path)
    args = parser.parse_args(); assemble(args.project.resolve(), args.comparison.resolve())
