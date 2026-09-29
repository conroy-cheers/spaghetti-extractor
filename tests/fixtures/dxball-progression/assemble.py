"""Add local progression and connected frame consumers to the source project."""
import argparse
import importlib.util
import json
from pathlib import Path
from spaghetti_extractor.candidate.source_export_bindings import render_source_service_bridges

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('progress_preparation',HERE/'prepare.py')
preparation=importlib.util.module_from_spec(spec);spec.loader.exec_module(preparation)

def assemble(project,comparison,connected):
    if not (project/'check-powerups.py').is_file():raise ValueError('start from the powerup source project')
    def write(name,text):
        p=project/name;p.parent.mkdir(parents=True,exist_ok=True)
        if not p.exists() or p.read_text()!=text:p.write_text(text)
    rendered=render_source_service_bridges(project/'lifted',bindings={'gameplay-progression':preparation.bridge_spec()})
    write('bridges/gameplay-progression/comparison-service-bridge.h',rendered['gameplay-progression'][0])
    write('bridges/gameplay-progression/bridge.c',preparation.bridge())
    for name,text in {'progress-runtime.h':preparation.runtime_header(),'progress-runtime.c':(HERE/'runtime.c').read_text(),
        'progression-state.h':(HERE/'progression-state.h').read_text(),'frame-progress.h':(HERE/'frame-progress.h').read_text()}.items():write('common/'+name,text)
    for name,check in [('progression',comparison),('progress-frame',connected)]:
        result=json.loads((check/'comparison-result.json').read_text())
        if result['status']!='match' or result['component_id']!='gameplay-progression':raise ValueError('requires matching progression comparisons')
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
    marker='# Gameplay progression and connected gameplay\n';base=(project/'Makefile').read_text().split(marker)[0]
    write('Makefile',base+'\n'+marker+'''all: progression progress-frame
progression: build/progress-runtime.o build/gameplay-progression.o lifted/liblifted.a
\t$(CC) $(LDFLAGS) build/progress-runtime.o build/gameplay-progression.o lifted/liblifted.a -o $@
progress-frame: build/progress-frame-runtime.o build/gameplay-progression.o build/gameplay-frame.o lifted/liblifted.a
\t$(CC) $(LDFLAGS) build/progress-frame-runtime.o build/gameplay-progression.o build/gameplay-frame.o lifted/liblifted.a -o $@
build/progress-runtime.o: common/progress-runtime.c
\t@mkdir -p build
\t$(CC) $(CFLAGS) -DDX_STANDALONE -Icommon -MMD -MP -c $< -o $@
build/progress-frame-runtime.o: common/progress-runtime.c
\t@mkdir -p build
\t$(CC) $(CFLAGS) -DDX_STANDALONE -DPROGRESS_CONNECTED -Icommon -MMD -MP -c $< -o $@
build/gameplay-progression.o: bridges/gameplay-progression/bridge.c bridges/gameplay-progression/comparison-service-bridge.h
\t@mkdir -p build
\t$(CC) $(CFLAGS) -Icommon -Ibridges/gameplay-progression -Ilifted/components/gameplay-progression/sources/generated -Ilifted/components/gameplay-progression/sources/source -Ilifted/components/gameplay-progression/sources/headers -MMD -MP -c $< -o $@
''')
    readme=(project/'README.md').read_text().replace('Twenty-nine components','Thirty components')
    paragraph='\nGameplay progression add `python check-progression.py` and `python check-progress-frame.py`. The latter executes four frames per case through the actual frame and progression components over shared state, without game startup or Wine.\n'
    write('README.md',readme if paragraph in readme else readme+paragraph)

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('project','comparison','connected'):p.add_argument(name,type=Path)
    a=p.parse_args();assemble(a.project.resolve(),a.comparison.resolve(),a.connected.resolve())
