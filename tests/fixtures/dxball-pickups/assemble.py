"""Add local pickup and two-component frame consumers to the source project."""
import argparse
import importlib.util
import json
from pathlib import Path
from spaghetti_extractor.candidate.source_export_bindings import render_source_service_bridges

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('pickup_preparation',HERE/'prepare.py')
preparation=importlib.util.module_from_spec(spec);spec.loader.exec_module(preparation)

def assemble(project,comparison,connected):
    if not (project/'check-bricks.py').is_file():raise ValueError('start from the brick source project')
    def write(name,text):
        p=project/name;p.parent.mkdir(parents=True,exist_ok=True)
        if not p.exists() or p.read_text()!=text:p.write_text(text)
    rendered=render_source_service_bridges(project/'lifted',bindings={'pickup-lifecycle':preparation.bridge_spec()})
    write('bridges/pickup-lifecycle/comparison-service-bridge.h',rendered['pickup-lifecycle'][0])
    write('bridges/pickup-lifecycle/bridge.c',preparation.bridge())
    for name,text in {'pickup-runtime.h':preparation.runtime_header(),'pickup-runtime.c':(HERE/'runtime.c').read_text(),
        'pickup-state.h':(HERE/'pickup-state.h').read_text(),'frame-pickups.h':(HERE/'frame-pickups.h').read_text()}.items():write('common/'+name,text)
    for name,check in [('pickups',comparison),('pickup-frame',connected)]:
        result=json.loads((check/'comparison-result.json').read_text())
        if result['status']!='match' or result['component_id']!='pickup-lifecycle':raise ValueError('requires matching pickup comparisons')
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
    marker='# Pickup lifecycle and connected gameplay\n';base=(project/'Makefile').read_text().split(marker)[0]
    write('Makefile',base+'\n'+marker+'''all: pickups pickup-frame
pickups: build/pickup-runtime.o build/pickup-lifecycle.o lifted/liblifted.a
\t$(CC) $(LDFLAGS) build/pickup-runtime.o build/pickup-lifecycle.o lifted/liblifted.a -o $@
pickup-frame: build/pickup-frame-runtime.o build/pickup-lifecycle.o build/gameplay-frame.o lifted/liblifted.a
\t$(CC) $(LDFLAGS) build/pickup-frame-runtime.o build/pickup-lifecycle.o build/gameplay-frame.o lifted/liblifted.a -o $@
build/pickup-runtime.o: common/pickup-runtime.c
\t@mkdir -p build
\t$(CC) $(CFLAGS) -DDX_STANDALONE -Icommon -MMD -MP -c $< -o $@
build/pickup-frame-runtime.o: common/pickup-runtime.c
\t@mkdir -p build
\t$(CC) $(CFLAGS) -DDX_STANDALONE -DPICKUP_CONNECTED -Icommon -MMD -MP -c $< -o $@
build/pickup-lifecycle.o: bridges/pickup-lifecycle/bridge.c bridges/pickup-lifecycle/comparison-service-bridge.h
\t@mkdir -p build
\t$(CC) $(CFLAGS) -Icommon -Ibridges/pickup-lifecycle -Ilifted/components/pickup-lifecycle/sources/generated -Ilifted/components/pickup-lifecycle/sources/source -Ilifted/components/pickup-lifecycle/sources/headers -MMD -MP -c $< -o $@
''')
    readme=(project/'README.md').read_text().replace('Twenty-three components','Twenty-four components')
    paragraph='\nPickup lifecycles add `python check-pickups.py` and `python check-pickup-frame.py`. The latter executes four frames per case through the actual frame and pickup component over shared state, without game startup or Wine.\n'
    write('README.md',readme if paragraph in readme else readme+paragraph)

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('project','comparison','connected'):p.add_argument(name,type=Path)
    a=p.parse_args();assemble(a.project.resolve(),a.comparison.resolve(),a.connected.resolve())
