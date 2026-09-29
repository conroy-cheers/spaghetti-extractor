"""Add the checked menu to the existing portable source project."""
import argparse
import importlib.util
import json
from pathlib import Path

from spaghetti_extractor.candidate.source_export_bindings import render_source_service_bridges

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('menu_preparation', HERE/'prepare.py')
preparation = importlib.util.module_from_spec(spec); spec.loader.exec_module(preparation)


def assemble(project, comparison):
    result = json.loads((comparison/'comparison-result.json').read_text())
    if result['status'] != 'match' or result['component_id'] != 'menu-scene': raise ValueError('requires matching menu comparison')
    if not (project/'common/scene-runtime.c').is_file(): raise ValueError('start from the title scene source project')
    def write(name, text):
        path = project/name; path.parent.mkdir(parents=True, exist_ok=True)
        if not path.exists() or path.read_text() != text: path.write_text(text)
    rendered = render_source_service_bridges(project/'lifted', bindings={'menu-scene':preparation.bridge_spec()})
    write('bridges/menu-scene/comparison-service-bridge.h', rendered['menu-scene'][0])
    write('bridges/menu-scene/bridge.c', preparation.bridge())
    write('common/menu-runtime.h', preparation.runtime_header())
    write('common/menu-state.h', (HERE/'menu-state.h').read_text())
    write('common/menu-common.h', preparation.common_adapters())
    write('common/menu-runtime.c', (HERE/'runtime.c').read_text())
    write('common/scene-runtime.c', (preparation.SCENE/'runtime.c').read_text())
    write('common/title-runtime.c', (preparation.scene.TITLE/'runtime.c').read_text())
    write('menu-cases.json', json.dumps([dict(id=row['id'],arguments=row['arguments'],
        expected=row['observations']['original']) for row in result['cases']],indent=2)+'\n')
    write('check-menu.py', '''import argparse,json,subprocess
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--runner',action='append',default=[])
a=p.parse_args();root=Path(__file__).resolve().parent;cases=json.loads((root/'menu-cases.json').read_text())
for case in cases:
    ran=subprocess.run([*a.runner,str(root/'menu'),'source',*case['arguments']],cwd=root,capture_output=True,text=True,timeout=30)
    if ran.returncode:raise RuntimeError(case['id']+': '+ran.stderr[-2000:])
    if json.loads(ran.stdout)!=case['expected']:raise RuntimeError(case['id']+': native observations differ')
print(str(len(cases))+' standalone menu cases match original x86 observations')
''')
    marker = '# Main menu consumer\n'; base = (project/'Makefile').read_text().split(marker)[0]
    write('Makefile',base+'\n'+marker+'''all: menu
menu: build/menu-runtime.o build/menu-scene.o build/title-scene.o build/title-animation.o build/cleanup-select.o build/cleanup-dispose.o build/cleanup-clear.o build/font-metrics.o build/font-render.o build/sprite-drawing.o lifted/liblifted.a
\t$(CC) $(LDFLAGS) build/menu-runtime.o build/menu-scene.o build/title-scene.o build/title-animation.o build/cleanup-select.o build/cleanup-dispose.o build/cleanup-clear.o build/font-metrics.o build/font-render.o build/sprite-drawing.o lifted/liblifted.a -o $@
build/menu-runtime.o: common/menu-runtime.c
\t@mkdir -p build
\t$(CC) $(CFLAGS) -DDX_STANDALONE -Icommon -MMD -MP -c $< -o $@
build/menu-scene.o: bridges/menu-scene/bridge.c bridges/menu-scene/comparison-service-bridge.h
\t@mkdir -p build
\t$(CC) $(CFLAGS) -Icommon -Ibridges/menu-scene -Ilifted/components/menu-scene/sources/generated -Ilifted/components/menu-scene/sources/source -Ilifted/components/menu-scene/sources/headers -MMD -MP -c $< -o $@
''')
    write('README.md','# DX-Ball connected source consumers\n\n'
        'Build with `make`; run `python check.py`, `python check-drawing.py`, `python check-lifecycle.py`, '
        '`python check-flow.py`, `python check-pcx.py`, `python check-title.py`, `python check-scene.py` and `python check-menu.py`. '
        'CC/AR select the compiler; check scripts accept --runner for another architecture. '
        'Thirteen components implement sprite loading, capture/restoration, text/drawing, cleanup, frame/scene control, '
        'PCX image/palette loading, title animation, title scene and main menu with dot animation. '
        'Platform backends and remaining scene/gameplay bodies still require lifting.\n')


if __name__ == '__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('project','comparison'): parser.add_argument(name,type=Path)
    args=parser.parse_args(); assemble(args.project.resolve(),args.comparison.resolve())
