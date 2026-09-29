"""Add native-checked damage tracking to the existing standalone source project."""
import argparse
import importlib.util
import json
from pathlib import Path

from spaghetti_extractor.candidate.source_export_bindings import render_source_service_bridges

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('damage_preparation',HERE/'prepare.py')
preparation=importlib.util.module_from_spec(spec);spec.loader.exec_module(preparation)


def assemble(project,comparison):
    result=json.loads((comparison/'comparison-result.json').read_text())
    if result['status']!='match' or result['component_id']!='damage-tracking': raise ValueError('requires matching damage comparison')
    if not (project/'check-render.py').is_file(): raise ValueError('start from the board-rendering source project')
    def write(name,text):
        path=project/name;path.parent.mkdir(parents=True,exist_ok=True)
        if not path.exists() or path.read_text()!=text:path.write_text(text)
    rendered=render_source_service_bridges(project/'lifted',bindings={'damage-tracking':preparation.bridge_spec()})
    write('bridges/damage-tracking/comparison-service-bridge.h',rendered['damage-tracking'][0])
    write('bridges/damage-tracking/bridge.c',preparation.bridge())
    for name,text in {'damage-runtime.h':preparation.runtime_header(),'damage-state.h':(HERE/'damage-state.h').read_text(),
        'damage-observation.h':(HERE/'damage-observation.h').read_text(),
        'title-runtime.c':(HERE.parent/'dxball-title-animation/runtime.c').read_text(),
        'damage-runtime.c':(HERE/'runtime.c').read_text()}.items():write('common/'+name,text)
    write('damage-cases.json',json.dumps([dict(id=row['id'],arguments=row['arguments'],expected=row['observations']['original'])
        for row in result['cases']],indent=2)+'\n')
    write('check-damage.py','''import argparse,json,subprocess
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--runner',action='append',default=[])
a=p.parse_args();root=Path(__file__).resolve().parent;cases=json.loads((root/'damage-cases.json').read_text())
for case in cases:
    ran=subprocess.run([*a.runner,str(root/'damage'),'source',*case['arguments']],cwd=root,capture_output=True,text=True,timeout=30)
    if ran.returncode:raise RuntimeError(case['id']+': '+ran.stderr[-2000:])
    if json.loads(ran.stdout)!=case['expected']:raise RuntimeError(case['id']+': native observations differ')
print(str(len(cases))+' standalone damage-tracking cases match original x86 observations')
''')
    marker='# Damage tracking consumer\n';base=(project/'Makefile').read_text().split(marker)[0]
    objects='build/damage-runtime.o build/damage-tracking.o build/title-scene.o build/title-animation.o build/cleanup-select.o build/cleanup-dispose.o build/cleanup-clear.o build/font-metrics.o build/font-render.o build/sprite-drawing.o'
    write('Makefile',base+'\n'+marker+f'''all: damage
damage: {objects} lifted/liblifted.a
\t$(CC) $(LDFLAGS) {objects} lifted/liblifted.a -o $@
build/damage-runtime.o: common/damage-runtime.c
\t@mkdir -p build
\t$(CC) $(CFLAGS) -DDX_STANDALONE -Icommon -MMD -MP -c $< -o $@
build/damage-tracking.o: bridges/damage-tracking/bridge.c bridges/damage-tracking/comparison-service-bridge.h
\t@mkdir -p build
\t$(CC) $(CFLAGS) -Icommon -Ibridges/damage-tracking -Ilifted/components/damage-tracking/sources/generated -Ilifted/components/damage-tracking/sources/source -Ilifted/components/damage-tracking/sources/headers -MMD -MP -c $< -o $@
''')
    text=(project/'README.md').read_text().replace('Eighteen components','Nineteen components')
    paragraph='\nDamage tracking adds queue/cursor/presentation operations. Run `python check-damage.py` without the original executable or game UI.\n'
    write('README.md',text if paragraph in text else text+paragraph)


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('project','comparison'):p.add_argument(name,type=Path)
    a=p.parse_args();assemble(a.project.resolve(),a.comparison.resolve())
