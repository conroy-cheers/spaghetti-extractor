"""Add local brick and three-component frame consumers to the source project."""
import argparse
import importlib.util
import json
from pathlib import Path
from spaghetti_extractor.candidate.source_export_bindings import render_source_service_bridges

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('brick_preparation',HERE/'prepare.py')
preparation=importlib.util.module_from_spec(spec);spec.loader.exec_module(preparation)

def assemble(project,comparison,connected):
    if not (project/'check-motion.py').is_file():raise ValueError('start from the ball-motion source project')
    def write(name,text):
        p=project/name;p.parent.mkdir(parents=True,exist_ok=True)
        if not p.exists() or p.read_text()!=text:p.write_text(text)
    rendered=render_source_service_bridges(project/'lifted',bindings={'brick-actions':preparation.bridge_spec()})
    write('bridges/brick-actions/comparison-service-bridge.h',rendered['brick-actions'][0])
    write('bridges/brick-actions/bridge.c',preparation.bridge())
    for name,text in {'brick-runtime.h':preparation.runtime_header(),'brick-runtime.c':(HERE/'runtime.c').read_text(),
        'brick-state.h':(HERE/'brick-state.h').read_text(),'connected.h':(HERE/'connected.h').read_text()}.items():write('common/'+name,text)
    for name,check in [('bricks',comparison),('brick-network',connected)]:
        result=json.loads((check/'comparison-result.json').read_text())
        if result['status']!='match' or result['component_id']!='brick-actions':raise ValueError('requires matching brick comparisons')
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
    marker='# Brick actions and connected gameplay\n'
    base,found,old=(project/'Makefile').read_text().partition(marker)
    suffix=''
    if found:
        _,separator,later=old.partition('\n# ')
        suffix=separator+later
    write('Makefile',base.rstrip()+'\n\n'+marker+'''all: bricks brick-network
bricks: build/brick-runtime.o build/brick-actions.o lifted/liblifted.a
\t$(CC) $(LDFLAGS) build/brick-runtime.o build/brick-actions.o lifted/liblifted.a -o $@
brick-network: build/brick-network-runtime.o build/brick-actions.o build/ball-motion.o build/gameplay-frame.o lifted/liblifted.a
\t$(CC) $(LDFLAGS) build/brick-network-runtime.o build/brick-actions.o build/ball-motion.o build/gameplay-frame.o lifted/liblifted.a -o $@
build/brick-runtime.o: common/brick-runtime.c
\t@mkdir -p build
\t$(CC) $(CFLAGS) -DDX_STANDALONE -Icommon -MMD -MP -c $< -o $@
build/brick-network-runtime.o: common/brick-runtime.c
\t@mkdir -p build
\t$(CC) $(CFLAGS) -DDX_STANDALONE -DBRICK_CONNECTED -Icommon -MMD -MP -c $< -o $@
build/brick-actions.o: bridges/brick-actions/bridge.c bridges/brick-actions/comparison-service-bridge.h
\t@mkdir -p build
\t$(CC) $(CFLAGS) -Icommon -Ibridges/brick-actions -Ilifted/components/brick-actions/sources/generated -Ilifted/components/brick-actions/sources/source -Ilifted/components/brick-actions/sources/headers -MMD -MP -c $< -o $@
'''+suffix)
    readme=(project/'README.md').read_text().replace('Twenty-two components','Twenty-three components')
    paragraph='\nBrick rules and effects add `python check-bricks.py` and `python check-brick-network.py`. The latter executes twelve frames per case through the actual frame, ball motion and brick component over shared state, without game startup or Wine.\n'
    write('README.md',readme if paragraph in readme else readme+paragraph)

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('project','comparison','connected'):p.add_argument(name,type=Path)
    a=p.parse_args();assemble(a.project.resolve(),a.comparison.resolve(),a.connected.resolve())
