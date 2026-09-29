"""Add the native-checked editor to the existing portable source project."""
import argparse
import importlib.util
import json
from pathlib import Path

from spaghetti_extractor.candidate.source_export_bindings import render_source_service_bridges

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('editor_preparation',HERE/'prepare.py')
preparation=importlib.util.module_from_spec(spec);spec.loader.exec_module(preparation)


def assemble(project,comparison):
    result=json.loads((comparison/'comparison-result.json').read_text())
    if result['status']!='match' or result['component_id']!='board-editor':raise ValueError('requires matching editor comparison')
    if not (project/'check-boards.py').is_file():raise ValueError('start from the board-data source project')
    def write(name,text):
        path=project/name;path.parent.mkdir(parents=True,exist_ok=True)
        if not path.exists() or path.read_text()!=text:path.write_text(text)
    rendered=render_source_service_bridges(project/'lifted',bindings={'board-editor':preparation.bridge_spec()})
    write('bridges/board-editor/comparison-service-bridge.h',rendered['board-editor'][0])
    write('bridges/board-editor/bridge.c',preparation.bridge())
    for name,text in {'editor-runtime.h':preparation.runtime_header(),'editor-common.h':preparation.common_adapters(),
        'editor-state.h':(HERE/'editor-state.h').read_text(),'editor-runtime.c':(HERE/'runtime.c').read_text(),
        'menu-runtime.c':(preparation.MENU/'runtime.c').read_text(),
        'scene-runtime.c':(preparation.menu.SCENE/'runtime.c').read_text()}.items():write('common/'+name,text)
    write('editor-cases.json',json.dumps([dict(id=row['id'],arguments=row['arguments'],expected=row['observations']['original'])
        for row in result['cases']],indent=2)+'\n')
    write('check-editor.py','''import argparse,json,subprocess
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--runner',action='append',default=[])
a=p.parse_args();root=Path(__file__).resolve().parent;cases=json.loads((root/'editor-cases.json').read_text())
for case in cases:
    ran=subprocess.run([*a.runner,str(root/'editor'),'source',*case['arguments']],cwd=root,capture_output=True,text=True,timeout=30)
    if ran.returncode:raise RuntimeError(case['id']+': '+ran.stderr[-2000:])
    if json.loads(ran.stdout)!=case['expected']:raise RuntimeError(case['id']+': native observations differ')
print(str(len(cases))+' standalone editor cases match original x86 observations')
''')
    marker='# Board editor consumer\n';base=(project/'Makefile').read_text().split(marker)[0]
    objects='build/editor-runtime.o build/board-editor.o build/board-data.o build/menu-scene.o build/title-scene.o build/title-animation.o build/cleanup-select.o build/cleanup-dispose.o build/cleanup-clear.o build/font-metrics.o build/font-render.o build/sprite-drawing.o'
    write('Makefile',base+'\n'+marker+f'''all: editor
editor: {objects} lifted/liblifted.a
\t$(CC) $(LDFLAGS) {objects} lifted/liblifted.a -o $@
build/editor-runtime.o: common/editor-runtime.c
\t@mkdir -p build
\t$(CC) $(CFLAGS) -DDX_STANDALONE -Icommon -MMD -MP -c $< -o $@
build/board-editor.o: bridges/board-editor/bridge.c bridges/board-editor/comparison-service-bridge.h
\t@mkdir -p build
\t$(CC) $(CFLAGS) -Icommon -Ibridges/board-editor -Ilifted/components/board-editor/sources/generated -Ilifted/components/board-editor/sources/source -Ilifted/components/board-editor/sources/headers -MMD -MP -c $< -o $@
''')
    text=(project/'README.md').read_text().replace('Sixteen components','Seventeen components')
    paragraph='\nThe board editor adds entry, redraw, input, keyboard, palette/status drawing and leave. Run `python check-editor.py`.\n'
    write('README.md',text if paragraph in text else text+paragraph)


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('project','comparison'):p.add_argument(name,type=Path)
    a=p.parse_args();assemble(a.project.resolve(),a.comparison.resolve())
