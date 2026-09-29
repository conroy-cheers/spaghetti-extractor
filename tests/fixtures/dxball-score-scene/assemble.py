"""Integrate the score screen into the existing standalone source project."""
import argparse
import importlib.util
import json
from pathlib import Path

from spaghetti_extractor.candidate.source_export_bindings import render_source_service_bridges

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('screen_preparation',HERE/'prepare.py')
preparation=importlib.util.module_from_spec(spec);spec.loader.exec_module(preparation)


def assemble(project,comparison):
    result=json.loads((comparison/'comparison-result.json').read_text())
    if result['status']!='match' or result['component_id']!='score-scene':raise ValueError('requires matching screen comparison')
    if not (project/'check-scores.py').is_file():raise ValueError('start from the score-table source project')
    def write(name,text):
        path=project/name;path.parent.mkdir(parents=True,exist_ok=True)
        if not path.exists() or path.read_text()!=text:path.write_text(text)
    rendered=render_source_service_bridges(project/'lifted',bindings={'score-scene':preparation.bridge_spec()})
    write('bridges/score-scene/comparison-service-bridge.h',rendered['score-scene'][0])
    write('bridges/score-scene/bridge.c',preparation.bridge())
    for name,text in {'screen-runtime.h':preparation.runtime_header(),'screen-common.h':preparation.common_adapters(),
        'screen-state.h':(HERE/'screen-state.h').read_text(),'screen-runtime.c':(HERE/'runtime.c').read_text(),
        'menu-runtime.c':(preparation.MENU/'runtime.c').read_text(),
        'scene-runtime.c':(preparation.menu.SCENE/'runtime.c').read_text()}.items():write('common/'+name,text)
    write('screen-cases.json',json.dumps([dict(id=row['id'],arguments=row['arguments'],expected=row['observations']['original'])
        for row in result['cases']],indent=2)+'\n')
    write('check-screen.py','''import argparse,json,subprocess
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--runner',action='append',default=[])
a=p.parse_args();root=Path(__file__).resolve().parent;cases=json.loads((root/'screen-cases.json').read_text())
for case in cases:
    ran=subprocess.run([*a.runner,str(root/'screen'),'source',*case['arguments']],cwd=root,capture_output=True,text=True,timeout=30)
    if ran.returncode:raise RuntimeError(case['id']+': '+ran.stderr[-2000:])
    if json.loads(ran.stdout)!=case['expected']:raise RuntimeError(case['id']+': native observations differ')
print(str(len(cases))+' standalone score-screen cases match original x86 observations')
''')
    marker='# Score screen consumer\n';base=(project/'Makefile').read_text().split(marker)[0]
    objects='build/screen-runtime.o build/score-scene.o build/score-table.o build/menu-scene.o build/title-scene.o build/title-animation.o build/cleanup-select.o build/cleanup-dispose.o build/cleanup-clear.o build/font-metrics.o build/font-render.o build/sprite-drawing.o'
    write('Makefile',base+'\n'+marker+f'''all: screen
screen: {objects} lifted/liblifted.a
\t$(CC) $(LDFLAGS) {objects} lifted/liblifted.a -o $@
build/screen-runtime.o: common/screen-runtime.c
\t@mkdir -p build
\t$(CC) $(CFLAGS) -DDX_STANDALONE -Icommon -MMD -MP -c $< -o $@
build/score-scene.o: bridges/score-scene/bridge.c bridges/score-scene/comparison-service-bridge.h
\t@mkdir -p build
\t$(CC) $(CFLAGS) -Icommon -Ibridges/score-scene -Ilifted/components/score-scene/sources/generated -Ilifted/components/score-scene/sources/source -Ilifted/components/score-scene/sources/headers -MMD -MP -c $< -o $@
''')
    text=(project/'README.md').read_text().replace('Fourteen components','Fifteen components')
    paragraph='\nThe score screen adds name editing, table rendering and scene transitions. Run `python check-screen.py`.\n'
    write('README.md',text if paragraph in text else text+paragraph)


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('project','comparison'):p.add_argument(name,type=Path)
    a=p.parse_args();assemble(a.project.resolve(),a.comparison.resolve())
