"""Integrate application bootstrap into the preceding standalone source selection."""
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
    if not (project/'check-palette.py').is_file():raise ValueError('requires the preceding palette source project')
    checked=json.loads((comparison/'comparison-result.json').read_text())
    if checked['status']!='match' or checked['component_id']!='application-bootstrap':raise ValueError('requires matching bootstrap comparison')
    rendered=render_source_service_bridges(project/'lifted',bindings={'application-bootstrap':AUTHOR['bridge_spec']()})
    write('bridges/application-bootstrap/comparison-service-bridge.h',rendered['application-bootstrap'][0]);write('bridges/application-bootstrap/bridge.c',AUTHOR['bridge']())
    write('common/bootstrap-state.h',(comparison/'inputs/source/bootstrap-state.h').read_text())
    write('common/bootstrap-runtime.c',(comparison/'inputs/adapters/runtime.c').read_text());write('common/bootstrap-runtime.h',AUTHOR['runtime_header']())
    cases=[dict(id=c['id'],arguments=['source',*c['arguments']],expected=c['observations']['original']) for c in checked['cases']]
    write('bootstrap-cases.json',json.dumps(cases,separators=(',',':'))+'\n')
    write('check-bootstrap.py','''import argparse,json,subprocess
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--runner',action='append',default=[])
a=p.parse_args();root=Path(__file__).resolve().parent
cases=json.loads((root/'bootstrap-cases.json').read_text())
for case in cases:
    ran=subprocess.run([*a.runner,str(root/'bootstrap'),*case['arguments']],capture_output=True,text=True,timeout=30)
    if ran.returncode:raise RuntimeError(case['id']+': '+ran.stderr[-2000:])
    observed=json.loads(ran.stdout)
    if observed!=case['expected']:raise RuntimeError(case['id']+': '+json.dumps(dict(expected=case['expected'],observed=observed)))
print(str(len(cases))+' application-bootstrap cases match retained original x86 observations')
''')
    marker='# Application bootstrap consumer\n';base,found,tail=(project/'Makefile').read_text().partition(marker);suffix=''
    if found:
        _,separator,later=tail.partition('\n# ');suffix=separator+later
    write('Makefile',base.rstrip()+'\n\n'+marker+'''all: bootstrap
bootstrap: build/bootstrap-runtime.o build/application-bootstrap.o lifted/liblifted.a
\t$(CC) $(LDFLAGS) $^ -o $@
build/bootstrap-runtime.o: common/bootstrap-runtime.c
\t@mkdir -p build
\t$(CC) $(CFLAGS) -DDX_STANDALONE -Icommon -MMD -MP -c $< -o $@
build/application-bootstrap.o: bridges/application-bootstrap/bridge.c bridges/application-bootstrap/comparison-service-bridge.h
\t@mkdir -p build
\t$(CC) $(CFLAGS) -Icommon -Ibridges/application-bootstrap -Ilifted/components/application-bootstrap/sources/generated -Ilifted/components/application-bootstrap/sources/source -Ilifted/components/application-bootstrap/sources/headers -MMD -MP -c $< -o $@
'''+suffix)
    note='\nApplication bootstrap: `python check-bootstrap.py` exercises initialization, resource publication, timing and RGB/flag bytes. AArch64 accepts `--runner /path/to/qemu-aarch64`.\n'
    current=(project/'README.md').read_text()
    if note not in current:write('README.md',current+note)

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for n in ('project','comparison'):p.add_argument(n,type=Path)
    a=p.parse_args();assemble(a.project.resolve(),a.comparison.resolve())
