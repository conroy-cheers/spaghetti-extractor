"""Add the independently executable application shell to a DX-Ball source project."""
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
    if not (project/'check-warning.py').is_file():raise ValueError('requires the existing DX-Ball source project')
    checked=json.loads((comparison/'comparison-result.json').read_text())
    if checked['status']!='match' or checked['component_id']!='application-shell':raise ValueError('requires matching application shell comparison')
    render=render_source_service_bridges(project/'lifted',bindings={'application-shell':AUTHOR['bridge_spec']()})
    write('bridges/application-shell/comparison-service-bridge.h',render['application-shell'][0])
    write('bridges/application-shell/bridge.c',AUTHOR['bridge']())
    write('common/shell-state.h',(HERE/'shell-state.h').read_text())
    write('common/shell-runtime.c',(HERE/'runtime.c').read_text())
    write('common/shell-runtime.h',AUTHOR['runtime_header']())
    cases=[dict(id=c['id'],arguments=['source',*c['arguments']],expected=c['observations']['original']) for c in checked['cases']]
    write('shell-cases.json',json.dumps(cases,separators=(',',':'))+'\n')
    write('check-shell.py','''import argparse,json,subprocess
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--runner',action='append',default=[])
a=p.parse_args();root=Path(__file__).resolve().parent
cases=json.loads((root/'shell-cases.json').read_text())
for case in cases:
    ran=subprocess.run([*a.runner,str(root/'shell'),*case['arguments']],capture_output=True,text=True,timeout=30)
    if ran.returncode:raise RuntimeError(case['id']+': '+ran.stderr[-2000:])
    observed=json.loads(ran.stdout)
    if observed!=case['expected']:raise RuntimeError(case['id']+': '+json.dumps(dict(expected=case['expected'],observed=observed)))
print(str(len(cases))+' application shell cases match retained original x86 observations')
''')
    marker='# Application shell consumer\n';base,found,tail=(project/'Makefile').read_text().partition(marker)
    suffix=''
    if found:
        _,separator,later=tail.partition('\n# ');suffix=separator+later
    write('Makefile',base.rstrip()+'\n\n'+marker+'''all: shell
shell: build/shell-runtime.o build/application-shell.o lifted/liblifted.a
\t$(CC) $(LDFLAGS) $^ -o $@
build/shell-runtime.o: common/shell-runtime.c
\t@mkdir -p build
\t$(CC) $(CFLAGS) -DDX_STANDALONE -Icommon -MMD -MP -c $< -o $@
build/application-shell.o: bridges/application-shell/bridge.c bridges/application-shell/comparison-service-bridge.h
\t@mkdir -p build
\t$(CC) $(CFLAGS) -Icommon -Ibridges/application-shell -Ilifted/components/application-shell/sources/generated -Ilifted/components/application-shell/sources/source -Ilifted/components/application-shell/sources/headers -MMD -MP -c $< -o $@
'''+suffix)
    note='\nApplication shell: `python check-shell.py` executes startup, message dispatch, callbacks and resource lifetime without Wine or the original image. Use `--runner /path/to/qemu-aarch64` for an AArch64 build. Platform operations are controlled services; this is not yet a portable desktop backend.\n'
    current=(project/'README.md').read_text()
    if note not in current:write('README.md',current+note)

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for n in ('project','comparison'):p.add_argument(n,type=Path)
    a=p.parse_args();assemble(a.project.resolve(),a.comparison.resolve())
