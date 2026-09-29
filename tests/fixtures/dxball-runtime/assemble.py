"""Integrate clock, wait and random state into the preceding standalone source selection."""
import argparse
import json
from pathlib import Path
import runpy
from spaghetti_extractor.candidate.source_export_bindings import render_source_service_bridges

HERE=Path(__file__).resolve().parent
AUTHOR=runpy.run_path(str(HERE/'prepare.py'))

def assemble(project,comparison):
    def write(name,text):
        p=project/name;p.parent.mkdir(parents=True,exist_ok=True)
        if not p.exists() or p.read_text()!=text:p.write_text(text)
    if not (project/'check-bootstrap.py').is_file():raise ValueError('requires the preceding bootstrap source project')
    checked=json.loads((comparison/'comparison-result.json').read_text())
    if checked['status']!='match' or checked['component_id']!='runtime-support':raise ValueError('requires matching runtime comparison')
    rendered=render_source_service_bridges(project/'lifted',bindings={'runtime-support':AUTHOR['bridge_spec']()})
    write('bridges/runtime-support/comparison-service-bridge.h',rendered['runtime-support'][0]);write('bridges/runtime-support/bridge.c',AUTHOR['bridge']())
    write('common/runtime-state.h',(comparison/'inputs/source/runtime-state.h').read_text())
    write('common/runtime-runtime.c',(comparison/'inputs/adapters/runtime.c').read_text());write('common/runtime-support.h',AUTHOR['runtime_header']())
    cases=[dict(id=c['id'],arguments=['source',*c['arguments']],expected=c['observations']['original']) for c in checked['cases']]
    write('runtime-cases.json',json.dumps(cases,separators=(',',':'))+'\n')
    write('check-runtime.py','''import argparse,json,subprocess
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--runner',action='append',default=[])
a=p.parse_args();root=Path(__file__).resolve().parent
cases=json.loads((root/'runtime-cases.json').read_text())
for case in cases:
    ran=subprocess.run([*a.runner,str(root/'runtime'),*case['arguments']],capture_output=True,text=True,timeout=30)
    if ran.returncode:raise RuntimeError(case['id']+': '+ran.stderr[-2000:])
    observed=json.loads(ran.stdout)
    if observed!=case['expected']:raise RuntimeError(case['id']+': '+json.dumps(dict(expected=case['expected'],observed=observed)))
print(str(len(cases))+' runtime-support cases match retained original x86 observations')
''')
    marker='# Application runtime consumer\n';base,found,tail=(project/'Makefile').read_text().partition(marker);suffix=''
    if found:
        _,separator,later=tail.partition('\n# ');suffix=separator+later
    write('Makefile',base.rstrip()+'\n\n'+marker+'''all: runtime
runtime: build/runtime-runtime.o build/runtime-support.o lifted/liblifted.a
\t$(CC) $(LDFLAGS) $^ -o $@
build/runtime-runtime.o: common/runtime-runtime.c
\t@mkdir -p build
\t$(CC) $(CFLAGS) -DDX_STANDALONE -Icommon -MMD -MP -c $< -o $@
build/runtime-support.o: bridges/runtime-support/bridge.c bridges/runtime-support/comparison-service-bridge.h
\t@mkdir -p build
\t$(CC) $(CFLAGS) -Icommon -Ibridges/runtime-support -Ilifted/components/runtime-support/sources/generated -Ilifted/components/runtime-support/sources/source -Ilifted/components/runtime-support/sources/headers -MMD -MP -c $< -o $@
'''+suffix)
    note='\nApplication runtime: `python check-runtime.py` exercises clock history, wait callbacks and shared random sequences. AArch64 accepts `--runner /path/to/qemu-aarch64`.\n'
    current=(project/'README.md').read_text()
    if note not in current:write('README.md',current+note)

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for n in ('project','comparison'):p.add_argument(n,type=Path)
    a=p.parse_args();assemble(a.project.resolve(),a.comparison.resolve())
