"""Add the independently executable display setup to a DX-Ball source project."""
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
    if not (project/'check-shell.py').is_file():raise ValueError('requires the existing DX-Ball source project')
    checked=json.loads((comparison/'comparison-result.json').read_text())
    if checked['status']!='match' or checked['component_id']!='display-setup':raise ValueError('requires matching display setup comparison')
    render=render_source_service_bridges(project/'lifted',bindings={'display-setup':AUTHOR['bridge_spec']()})
    write('bridges/display-setup/comparison-service-bridge.h',render['display-setup'][0])
    write('bridges/display-setup/bridge.c',AUTHOR['bridge']())
    write('common/display-state.h',(HERE/'display-state.h').read_text())
    write('common/display-runtime.c',(HERE/'runtime.c').read_text())
    write('common/display-runtime.h',AUTHOR['runtime_header']())
    cases=[dict(id=c['id'],arguments=['source',*c['arguments']],expected=c['observations']['original']) for c in checked['cases']]
    write('display-cases.json',json.dumps(cases,separators=(',',':'))+'\n')
    write('check-display.py','''import argparse,json,subprocess
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--runner',action='append',default=[])
a=p.parse_args();root=Path(__file__).resolve().parent
cases=json.loads((root/'display-cases.json').read_text())
for case in cases:
    ran=subprocess.run([*a.runner,str(root/'display'),*case['arguments']],capture_output=True,text=True,timeout=30)
    if ran.returncode:raise RuntimeError(case['id']+': '+ran.stderr[-2000:])
    observed=json.loads(ran.stdout)
    if observed!=case['expected']:raise RuntimeError(case['id']+': '+json.dumps(dict(expected=case['expected'],observed=observed)))
print(str(len(cases))+' display setup cases match retained original x86 observations')
''')
    marker='# Display setup consumer\n';base,found,tail=(project/'Makefile').read_text().partition(marker)
    suffix=''
    if found:
        _,separator,later=tail.partition('\n# ');suffix=separator+later
    write('Makefile',base.rstrip()+'\n\n'+marker+'''all: display
display: build/display-runtime.o build/display-setup.o lifted/liblifted.a
\t$(CC) $(LDFLAGS) $^ -o $@
build/display-runtime.o: common/display-runtime.c
\t@mkdir -p build
\t$(CC) $(CFLAGS) -DDX_STANDALONE -Icommon -MMD -MP -c $< -o $@
build/display-setup.o: bridges/display-setup/bridge.c bridges/display-setup/comparison-service-bridge.h
\t@mkdir -p build
\t$(CC) $(CFLAGS) -Icommon -Ibridges/display-setup -Ilifted/components/display-setup/sources/generated -Ilifted/components/display-setup/sources/source -Ilifted/components/display-setup/sources/headers -MMD -MP -c $< -o $@
'''+suffix)
    note='\nDisplay setup: `python check-display.py` executes window creation, display setup, callbacks and resource lifetime without Wine or the original image. Use `--runner /path/to/qemu-aarch64` for an AArch64 build. Platform operations are controlled services; this is not yet a portable desktop backend.\n'
    current=(project/'README.md').read_text()
    if note not in current:write('README.md',current+note)

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for n in ('project','comparison'):p.add_argument(n,type=Path)
    a=p.parse_args();assemble(a.project.resolve(),a.comparison.resolve())
