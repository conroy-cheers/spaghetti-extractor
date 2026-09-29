"""Add local particle and two-component frame consumers to the source project."""
import argparse
import importlib.util
import json
from pathlib import Path
from spaghetti_extractor.candidate.source_export_bindings import render_source_service_bridges

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('particle_preparation',HERE/'prepare.py')
preparation=importlib.util.module_from_spec(spec);spec.loader.exec_module(preparation)

def assemble(project,comparison,connected):
    if not (project/'check-pickups.py').is_file():raise ValueError('start from the pickup source project')
    def write(name,text):
        p=project/name;p.parent.mkdir(parents=True,exist_ok=True)
        if not p.exists() or p.read_text()!=text:p.write_text(text)
    rendered=render_source_service_bridges(project/'lifted',bindings={'particle-lifecycle':preparation.bridge_spec()})
    write('bridges/particle-lifecycle/comparison-service-bridge.h',rendered['particle-lifecycle'][0])
    write('bridges/particle-lifecycle/bridge.c',preparation.bridge())
    for name,text in {'particle-runtime.h':preparation.runtime_header(),'particle-runtime.c':(HERE/'runtime.c').read_text(),
        'particle-state.h':(HERE/'particle-state.h').read_text(),'frame-particles.h':(HERE/'frame-particles.h').read_text()}.items():write('common/'+name,text)
    for name,check in [('particles',comparison),('particle-frame',connected)]:
        result=json.loads((check/'comparison-result.json').read_text())
        if result['status']!='match' or result['component_id']!='particle-lifecycle':raise ValueError('requires matching particle comparisons')
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
    marker='# Particle lifecycle and connected gameplay\n';base=(project/'Makefile').read_text().split(marker)[0]
    write('Makefile',base+'\n'+marker+'''all: particles particle-frame
particles: build/particle-runtime.o build/particle-lifecycle.o lifted/liblifted.a
\t$(CC) $(LDFLAGS) build/particle-runtime.o build/particle-lifecycle.o lifted/liblifted.a -o $@
particle-frame: build/particle-frame-runtime.o build/particle-lifecycle.o build/gameplay-frame.o lifted/liblifted.a
\t$(CC) $(LDFLAGS) build/particle-frame-runtime.o build/particle-lifecycle.o build/gameplay-frame.o lifted/liblifted.a -o $@
build/particle-runtime.o: common/particle-runtime.c
\t@mkdir -p build
\t$(CC) $(CFLAGS) -DDX_STANDALONE -Icommon -MMD -MP -c $< -o $@
build/particle-frame-runtime.o: common/particle-runtime.c
\t@mkdir -p build
\t$(CC) $(CFLAGS) -DDX_STANDALONE -DPARTICLE_CONNECTED -Icommon -MMD -MP -c $< -o $@
build/particle-lifecycle.o: bridges/particle-lifecycle/bridge.c bridges/particle-lifecycle/comparison-service-bridge.h
\t@mkdir -p build
\t$(CC) $(CFLAGS) -Icommon -Ibridges/particle-lifecycle -Ilifted/components/particle-lifecycle/sources/generated -Ilifted/components/particle-lifecycle/sources/source -Ilifted/components/particle-lifecycle/sources/headers -MMD -MP -c $< -o $@
''')
    readme=(project/'README.md').read_text().replace('Twenty-four components','Twenty-five components')
    paragraph='\nParticle lifecycles add `python check-particles.py` and `python check-particle-frame.py`. The latter executes eight frames per case through the actual frame and particle component over shared state, without game startup or Wine.\n'
    write('README.md',readme if paragraph in readme else readme+paragraph)

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('project','comparison','connected'):p.add_argument(name,type=Path)
    a=p.parse_args();assemble(a.project.resolve(),a.comparison.resolve(),a.connected.resolve())
