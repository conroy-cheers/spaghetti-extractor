"""Add local round-cleanup and connected frame consumers to the source project."""
import argparse
import importlib.util
import json
from pathlib import Path
from spaghetti_extractor.candidate.source_export_bindings import render_source_service_bridges

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('round_preparation',HERE/'prepare.py')
preparation=importlib.util.module_from_spec(spec);spec.loader.exec_module(preparation)

def assemble(project,comparison,connected):
    if not (project/'check-progression.py').is_file():raise ValueError('start from the progression source project')
    def write(name,text):
        p=project/name;p.parent.mkdir(parents=True,exist_ok=True)
        if not p.exists() or p.read_text()!=text:p.write_text(text)
    rendered=render_source_service_bridges(project/'lifted',bindings={'round-cleanup':preparation.bridge_spec()})
    write('bridges/round-cleanup/comparison-service-bridge.h',rendered['round-cleanup'][0])
    write('bridges/round-cleanup/bridge.c',preparation.bridge())
    for name,text in {'round-runtime.h':preparation.runtime_header(),'round-runtime.c':(HERE/'runtime.c').read_text(),
        'round-state.h':(HERE/'round-state.h').read_text(),'progress-consumer.h':(HERE/'progress-consumer.h').read_text(),'connected-run.h':(HERE/'connected-run.h').read_text()}.items():write('common/'+name,text)
    for name,check in [('round-cleanup',comparison),('round-connected',connected)]:
        result=json.loads((check/'comparison-result.json').read_text())
        if result['status']!='match' or result['component_id']!='round-cleanup':raise ValueError('requires matching round-cleanup comparisons')
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
    marker='# Round cleanup and connected gameplay\n';base=(project/'Makefile').read_text().split(marker)[0]
    write('Makefile',base+'\n'+marker+'''all: round-cleanup round-connected
round-cleanup: build/round-runtime.o build/round-cleanup.o lifted/liblifted.a
\t$(CC) $(LDFLAGS) build/round-runtime.o build/round-cleanup.o lifted/liblifted.a -o $@
round-connected: build/round-connected-runtime.o build/round-cleanup.o build/gameplay-progression.o lifted/liblifted.a
\t$(CC) $(LDFLAGS) build/round-connected-runtime.o build/round-cleanup.o build/gameplay-progression.o lifted/liblifted.a -o $@
build/round-runtime.o: common/round-runtime.c
\t@mkdir -p build
\t$(CC) $(CFLAGS) -DDX_STANDALONE -Icommon -MMD -MP -c $< -o $@
build/round-connected-runtime.o: common/round-runtime.c
\t@mkdir -p build
\t$(CC) $(CFLAGS) -DDX_STANDALONE -DROUND_CONNECTED -Icommon -MMD -MP -c $< -o $@
build/round-cleanup.o: bridges/round-cleanup/bridge.c bridges/round-cleanup/comparison-service-bridge.h
\t@mkdir -p build
\t$(CC) $(CFLAGS) -Icommon -Ibridges/round-cleanup -Ilifted/components/round-cleanup/sources/generated -Ilifted/components/round-cleanup/sources/source -Ilifted/components/round-cleanup/sources/headers -MMD -MP -c $< -o $@
''')
    readme=(project/'README.md').read_text().replace('Thirty components','Thirty-one components')
    paragraph='\nRound cleanup adds `python check-round-cleanup.py` and `python check-round-connected.py`. The latter executes actual round transitions and cleanup over shared state, without game startup or Wine.\n'
    write('README.md',readme if paragraph in readme else readme+paragraph)

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('project','comparison','connected'):p.add_argument(name,type=Path)
    a=p.parse_args();assemble(a.project.resolve(),a.comparison.resolve(),a.connected.resolve())
