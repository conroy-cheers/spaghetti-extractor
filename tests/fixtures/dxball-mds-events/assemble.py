"""Add the checked MDS event expander and its retained consumer to a source project."""
import argparse
import json
from pathlib import Path
import runpy
import shutil

HERE=Path(__file__).resolve().parent
AUTHOR=runpy.run_path(str(HERE/'prepare.py'))

def assemble(project,comparison):
    def write(name,text):
        p=project/name;p.parent.mkdir(parents=True,exist_ok=True)
        if not p.exists() or p.read_text()!=text:p.write_text(text)
    if not (project/'check-music.py').is_file():raise ValueError('requires preceding music source project')
    checked=json.loads((comparison/'comparison-result.json').read_text())
    if checked['status']!='match' or checked['component_id']!='mds-events':raise ValueError('requires matching MDS event comparison')
    write('bridges/mds-events/bridge.c',AUTHOR['bridge']())
    write('common/mds-events-state.h',(comparison/'inputs/source/mds-events-state.h').read_text())
    write('common/mds-events-runtime.c',(comparison/'inputs/adapters/runtime.c').read_text())
    write('common/mds-events-runtime.h',AUTHOR['runtime_header']())
    for name in AUTHOR['ASSETS']:shutil.copyfile(comparison/'inputs/runtime'/name,project/name)
    cases=[dict(id=c['id'],arguments=['source',*c['arguments']],expected=c['observations']['original']) for c in checked['cases']]
    write('mds-events-cases.json',json.dumps(cases,separators=(',',':'))+'\n')
    write('check-mds-events.py','''import argparse,json,subprocess
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--runner',action='append',default=[])
a=p.parse_args();root=Path(__file__).resolve().parent
cases=json.loads((root/'mds-events-cases.json').read_text())
for case in cases:
    ran=subprocess.run([*a.runner,str(root/'mds-events'),*case['arguments']],cwd=root,capture_output=True,text=True,timeout=30)
    if ran.returncode:raise RuntimeError(case['id']+': '+ran.stderr[-2000:])
    observed=json.loads(ran.stdout)
    if observed!=case['expected']:raise RuntimeError(case['id']+': observations differ from retained x86 execution')
print(str(len(cases))+' MDS event cases match retained original x86 observations')
''')
    marker='# MDS event consumer\n';base,found,tail=(project/'Makefile').read_text().partition(marker);suffix=''
    if found:
        _,separator,later=tail.partition('\n# ');suffix=separator+later
    write('Makefile',base.rstrip()+'\n\n'+marker+'''all: mds-events
mds-events: build/mds-events-runtime.o build/mds-events.o lifted/liblifted.a
\t$(CC) $(LDFLAGS) $^ -o $@
build/mds-events-runtime.o: common/mds-events-runtime.c
\t@mkdir -p build
\t$(CC) $(CFLAGS) -DDX_STANDALONE -Icommon -MMD -MP -c $< -o $@
build/mds-events.o: bridges/mds-events/bridge.c
\t@mkdir -p build
\t$(CC) $(CFLAGS) -Icommon -Ilifted/components/mds-events/sources/generated -Ilifted/components/mds-events/sources/source -MMD -MP -c $< -o $@
'''+suffix)
    note='\nMDS event expansion: `python check-mds-events.py` compares complete outputs and failure writes with retained x86 executions, including every block of all six bundled music files. AArch64 accepts `--runner /path/to/qemu-aarch64`.\n'
    current=(project/'README.md').read_text()
    if note not in current:write('README.md',current+note)

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('project','comparison'):p.add_argument(name,type=Path)
    a=p.parse_args();assemble(a.project.resolve(),a.comparison.resolve())
