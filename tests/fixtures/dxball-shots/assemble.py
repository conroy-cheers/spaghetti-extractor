"""Add local shot and connected frame consumers to the source project."""
import argparse
import importlib.util
import json
from pathlib import Path
from spaghetti_extractor.candidate.source_export_bindings import render_source_service_bridges

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('shot_preparation',HERE/'prepare.py')
preparation=importlib.util.module_from_spec(spec);spec.loader.exec_module(preparation)

def assemble(project,comparison,connected):
    if not (project/'check-paddles.py').is_file():raise ValueError('start from the paddle source project')
    def write(name,text):
        p=project/name;p.parent.mkdir(parents=True,exist_ok=True)
        if not p.exists() or p.read_text()!=text:p.write_text(text)
    rendered=render_source_service_bridges(project/'lifted',bindings={'shot-lifecycle':preparation.bridge_spec()})
    write('bridges/shot-lifecycle/comparison-service-bridge.h',rendered['shot-lifecycle'][0])
    write('bridges/shot-lifecycle/bridge.c',preparation.bridge())
    for name,text in {'shot-runtime.h':preparation.runtime_header(),'shot-runtime.c':(HERE/'runtime.c').read_text(),
        'frame-shots.h':(HERE/'frame-shots.h').read_text()}.items():write('common/'+name,text)
    for name,check in [('shots',comparison),('shot-frame',connected)]:
        result=json.loads((check/'comparison-result.json').read_text())
        if result['status']!='match' or result['component_id']!='shot-lifecycle':raise ValueError('requires matching shot comparisons')
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
    marker='# Shot lifecycle and connected gameplay\n';base=(project/'Makefile').read_text().split(marker)[0]
    write('Makefile',base+'\n'+marker+'''all: shots shot-frame
shots: build/shot-runtime.o build/shot-lifecycle.o lifted/liblifted.a
\t$(CC) $(LDFLAGS) build/shot-runtime.o build/shot-lifecycle.o lifted/liblifted.a -o $@
shot-frame: build/shot-frame-runtime.o build/shot-lifecycle.o build/gameplay-frame.o lifted/liblifted.a
\t$(CC) $(LDFLAGS) build/shot-frame-runtime.o build/shot-lifecycle.o build/gameplay-frame.o lifted/liblifted.a -o $@
build/shot-runtime.o: common/shot-runtime.c
\t@mkdir -p build
\t$(CC) $(CFLAGS) -DDX_STANDALONE -Icommon -MMD -MP -c $< -o $@
build/shot-frame-runtime.o: common/shot-runtime.c
\t@mkdir -p build
\t$(CC) $(CFLAGS) -DDX_STANDALONE -DSHOT_CONNECTED -Icommon -MMD -MP -c $< -o $@
build/shot-lifecycle.o: bridges/shot-lifecycle/bridge.c bridges/shot-lifecycle/comparison-service-bridge.h
\t@mkdir -p build
\t$(CC) $(CFLAGS) -Icommon -Ibridges/shot-lifecycle -Ilifted/components/shot-lifecycle/sources/generated -Ilifted/components/shot-lifecycle/sources/source -Ilifted/components/shot-lifecycle/sources/headers -MMD -MP -c $< -o $@
''')
    readme=(project/'README.md').read_text().replace('Twenty-six components','Twenty-seven components')
    paragraph='\nShot lifecycles add `python check-shots.py` and `python check-shot-frame.py`. The latter executes eight frames per case through the actual frame and shot components over shared state, without game startup or Wine.\n'
    write('README.md',readme if paragraph in readme else readme+paragraph)

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('project','comparison','connected'):p.add_argument(name,type=Path)
    a=p.parse_args();assemble(a.project.resolve(),a.comparison.resolve(),a.connected.resolve())
