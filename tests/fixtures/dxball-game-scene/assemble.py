"""Add gameplay scene and connected progression consumers to the source project."""
import argparse
import importlib.util
import json
from pathlib import Path
from spaghetti_extractor.candidate.source_export_bindings import render_source_service_bridges

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('game_preparation',HERE/'prepare.py')
preparation=importlib.util.module_from_spec(spec);spec.loader.exec_module(preparation)

def assemble(project,comparison,connected):
    if not (project/'check-round-cleanup.py').is_file():raise ValueError('start from the round-cleanup source project')
    def write(name,text):
        p=project/name;p.parent.mkdir(parents=True,exist_ok=True)
        if not p.exists() or p.read_text()!=text:p.write_text(text)
    rendered=render_source_service_bridges(project/'lifted',bindings={'gameplay-scene':preparation.bridge_spec()})
    write('bridges/gameplay-scene/comparison-service-bridge.h',rendered['gameplay-scene'][0])
    write('bridges/gameplay-scene/bridge.c',preparation.bridge())
    for name,text in {'game-runtime.h':preparation.runtime_header(),'game-runtime.c':(HERE/'runtime.c').read_text(),
        'game-state.h':(HERE/'game-state.h').read_text(),'progress-consumer.h':(HERE/'progress-consumer.h').read_text(),
        'game-native.h':(HERE/'game-native.h').read_text(),'game-services.h':(HERE/'game-services.h').read_text(),'connected-native.h':(HERE/'connected-native.h').read_text()}.items():write('common/game-scene/'+name,text)
    for name,check in [('gameplay-scene',comparison),('game-connected',connected)]:
        result=json.loads((check/'comparison-result.json').read_text())
        if result['status']!='match' or result['component_id']!='gameplay-scene':raise ValueError('requires matching gameplay-scene comparisons')
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
    marker='# Gameplay scene and connected progression\n';base=(project/'Makefile').read_text().split(marker)[0]
    write('Makefile',base+'\n'+marker+'''all: gameplay-scene game-connected
gameplay-scene: build/game-runtime.o build/gameplay-scene.o lifted/liblifted.a
\t$(CC) $(LDFLAGS) build/game-runtime.o build/gameplay-scene.o lifted/liblifted.a -o $@
game-connected: build/game-connected-runtime.o build/gameplay-scene.o build/gameplay-progression.o lifted/liblifted.a
\t$(CC) $(LDFLAGS) build/game-connected-runtime.o build/gameplay-scene.o build/gameplay-progression.o lifted/liblifted.a -o $@
build/game-runtime.o: common/game-scene/game-runtime.c
\t@mkdir -p build
\t$(CC) $(CFLAGS) -DDX_STANDALONE -Icommon/game-scene -Icommon -MMD -MP -c $< -o $@
build/game-connected-runtime.o: common/game-scene/game-runtime.c
\t@mkdir -p build
\t$(CC) $(CFLAGS) -DDX_STANDALONE -DGAME_CONNECTED -Icommon/game-scene -Icommon -MMD -MP -c $< -o $@
build/gameplay-scene.o: bridges/gameplay-scene/bridge.c bridges/gameplay-scene/comparison-service-bridge.h
\t@mkdir -p build
\t$(CC) $(CFLAGS) -Icommon/game-scene -Icommon -Ibridges/gameplay-scene -Ilifted/components/gameplay-scene/sources/generated -Ilifted/components/gameplay-scene/sources/source -Ilifted/components/gameplay-scene/sources/headers -MMD -MP -c $< -o $@
''')
    readme=(project/'README.md').read_text().replace('Thirty-one components','Thirty-two components')
    paragraph='\nGameplay scene adds `python check-gameplay-scene.py` and `python check-game-connected.py`. The latter executes actual scene entry, redraw, pause and restart over shared state, without game startup or Wine.\n'
    write('README.md',readme if paragraph in readme else readme+paragraph)

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('project','comparison','connected'):p.add_argument(name,type=Path)
    a=p.parse_args();assemble(a.project.resolve(),a.comparison.resolve(),a.connected.resolve())
