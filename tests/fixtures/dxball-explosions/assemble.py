"""Add local explosion and connected frame consumers to the source project."""
import argparse
import importlib.util
import json
from pathlib import Path
from spaghetti_extractor.candidate.source_export_bindings import render_source_service_bridges

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('explosion_preparation',HERE/'prepare.py')
preparation=importlib.util.module_from_spec(spec);spec.loader.exec_module(preparation)

def assemble(project,comparison,connected):
    if not (project/'check-shots.py').is_file():raise ValueError('start from the shot source project')
    def write(name,text):
        p=project/name;p.parent.mkdir(parents=True,exist_ok=True)
        if not p.exists() or p.read_text()!=text:p.write_text(text)
    rendered=render_source_service_bridges(project/'lifted',bindings={'explosion-lifecycle':preparation.bridge_spec()})
    write('bridges/explosion-lifecycle/comparison-service-bridge.h',rendered['explosion-lifecycle'][0])
    write('bridges/explosion-lifecycle/bridge.c',preparation.bridge())
    for name,text in {'explosion-runtime.h':preparation.runtime_header(),'explosion-runtime.c':(HERE/'runtime.c').read_text(),
        'explosion-state.h':(HERE/'explosion-state.h').read_text(),'frame-explosions.h':(HERE/'frame-explosions.h').read_text()}.items():write('common/'+name,text)
    for name,check in [('explosions',comparison),('explosion-frame',connected)]:
        result=json.loads((check/'comparison-result.json').read_text())
        if result['status']!='match' or result['component_id']!='explosion-lifecycle':raise ValueError('requires matching explosion comparisons')
        cases=[dict(id=c['id'],arguments=c['arguments'],expected=c['observations']['original']) for c in result['cases']]
        write(name+'-cases.json',json.dumps(cases,separators=(',',':'))+'\n')
        write('check-'+name+'.py',f'''import argparse,json,subprocess
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--runner',action='append',default=[])
a=p.parse_args();root=Path(__file__).resolve().parent;cases=json.loads((root/{(name+'-cases.json')!r}).read_text())
for case in cases:
    ran=subprocess.run([*a.runner,str(root/{name!r}),'source',*case['arguments']],cwd=root,capture_output=True,text=True,timeout=30)
    if ran.returncode:raise RuntimeError(case['id']+': '+ran.stderr[-2000:])
    if json.loads(ran.stdout)!=case['expected']:raise RuntimeError(case['id']+': native observations differ')
print(str(len(cases))+' {name} cases match original x86 observations')
''')
    marker='# Explosion lifecycle and connected gameplay\n';base=(project/'Makefile').read_text().split(marker)[0]
    write('Makefile',base+'\n'+marker+'''all: explosions explosion-frame
explosions: build/explosion-runtime.o build/explosion-lifecycle.o lifted/liblifted.a
\t$(CC) $(LDFLAGS) build/explosion-runtime.o build/explosion-lifecycle.o lifted/liblifted.a -o $@
explosion-frame: build/explosion-frame-runtime.o build/explosion-lifecycle.o build/gameplay-frame.o build/ball-motion.o lifted/liblifted.a
\t$(CC) $(LDFLAGS) build/explosion-frame-runtime.o build/explosion-lifecycle.o build/gameplay-frame.o build/ball-motion.o lifted/liblifted.a -o $@
build/explosion-runtime.o: common/explosion-runtime.c
\t@mkdir -p build
\t$(CC) $(CFLAGS) -DDX_STANDALONE -Icommon -MMD -MP -c $< -o $@
build/explosion-frame-runtime.o: common/explosion-runtime.c
\t@mkdir -p build
\t$(CC) $(CFLAGS) -DDX_STANDALONE -DEXPLOSION_CONNECTED -Icommon -MMD -MP -c $< -o $@
build/explosion-lifecycle.o: bridges/explosion-lifecycle/bridge.c bridges/explosion-lifecycle/comparison-service-bridge.h
\t@mkdir -p build
\t$(CC) $(CFLAGS) -Icommon -Ibridges/explosion-lifecycle -Ilifted/components/explosion-lifecycle/sources/generated -Ilifted/components/explosion-lifecycle/sources/source -Ilifted/components/explosion-lifecycle/sources/headers -MMD -MP -c $< -o $@
''')
    readme=(project/'README.md').read_text().replace('Twenty-seven components','Twenty-eight components')
    paragraph='\nExplosion lifecycles add `python check-explosions.py` and `python check-explosion-frame.py`. The latter executes twenty-six frames per case through the actual frame, ball-motion and explosion components over shared state, without game startup or Wine.\n'
    write('README.md',readme if paragraph in readme else readme+paragraph)

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('project','comparison','connected'):p.add_argument(name,type=Path)
    a=p.parse_args();assemble(a.project.resolve(),a.comparison.resolve(),a.connected.resolve())
