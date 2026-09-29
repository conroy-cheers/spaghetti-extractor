"""Add native-checked board rendering to the existing standalone source project."""
import argparse
import importlib.util
import json
from pathlib import Path

from spaghetti_extractor.candidate.source_export_bindings import render_source_service_bridges

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('render_preparation',HERE/'prepare.py')
preparation=importlib.util.module_from_spec(spec);spec.loader.exec_module(preparation)


def assemble(project,comparison):
    result=json.loads((comparison/'comparison-result.json').read_text())
    if result['status']!='match' or result['component_id']!='board-rendering':raise ValueError('requires matching renderer comparison')
    if not (project/'check-editor.py').is_file():raise ValueError('start from the editor source project')
    def write(name,text):
        path=project/name;path.parent.mkdir(parents=True,exist_ok=True)
        if not path.exists() or path.read_text()!=text:path.write_text(text)
    rendered=render_source_service_bridges(project/'lifted',bindings={'board-rendering':preparation.bridge_spec()})
    write('bridges/board-rendering/comparison-service-bridge.h',rendered['board-rendering'][0])
    write('bridges/board-rendering/bridge.c',preparation.bridge())
    for name,text in {'render-runtime.h':preparation.runtime_header(),'render-state.h':(HERE/'render-state.h').read_text(),
        'render-runtime.c':(HERE/'runtime.c').read_text(),
        'title-runtime.c':(HERE.parent/'dxball-title-animation/runtime.c').read_text()}.items():write('common/'+name,text)
    write('render-cases.json',json.dumps([dict(id=row['id'],arguments=row['arguments'],expected=row['observations']['original'])
        for row in result['cases']],indent=2)+'\n')
    write('check-render.py','''import argparse,json,subprocess
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--runner',action='append',default=[])
a=p.parse_args();root=Path(__file__).resolve().parent;cases=json.loads((root/'render-cases.json').read_text())
for case in cases:
    ran=subprocess.run([*a.runner,str(root/'render'),'source',*case['arguments']],cwd=root,capture_output=True,text=True,timeout=30)
    if ran.returncode:raise RuntimeError(case['id']+': '+ran.stderr[-2000:])
    if json.loads(ran.stdout)!=case['expected']:raise RuntimeError(case['id']+': native observations differ')
print(str(len(cases))+' standalone board-rendering cases match original x86 observations')
''')
    marker='# Board rendering consumer\n';base=(project/'Makefile').read_text().split(marker)[0]
    objects='build/render-runtime.o build/board-rendering.o build/menu-scene.o build/title-scene.o build/title-animation.o build/cleanup-select.o build/cleanup-dispose.o build/cleanup-clear.o build/font-metrics.o build/font-render.o build/sprite-drawing.o'
    write('Makefile',base+'\n'+marker+f'''all: render
render: {objects} lifted/liblifted.a
\t$(CC) $(LDFLAGS) {objects} lifted/liblifted.a -o $@
build/render-runtime.o: common/render-runtime.c
\t@mkdir -p build
\t$(CC) $(CFLAGS) -DDX_STANDALONE -Icommon -MMD -MP -c $< -o $@
build/board-rendering.o: bridges/board-rendering/bridge.c bridges/board-rendering/comparison-service-bridge.h
\t@mkdir -p build
\t$(CC) $(CFLAGS) -Icommon -Ibridges/board-rendering -Ilifted/components/board-rendering/sources/generated -Ilifted/components/board-rendering/sources/source -Ilifted/components/board-rendering/sources/headers -MMD -MP -c $< -o $@
''')
    text=(project/'README.md').read_text().replace('Seventeen components','Eighteen components')
    paragraph='\nBoard rendering adds the full-grid loop and scene-dependent cell drawing. Run `python check-render.py`.\n'
    write('README.md',text if paragraph in text else text+paragraph)


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('project','comparison'):p.add_argument(name,type=Path)
    a=p.parse_args();assemble(a.project.resolve(),a.comparison.resolve())
