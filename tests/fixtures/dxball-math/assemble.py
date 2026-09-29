"""Add a portable numeric consumer to the preceding source project."""
import argparse
import json
from pathlib import Path
import runpy
HERE=Path(__file__).resolve().parent
AUTHOR=runpy.run_path(str(HERE/'prepare.py'))

def assemble(project,comparison):
    def write(name,text):
        p=project/name;p.parent.mkdir(parents=True,exist_ok=True)
        if not p.exists() or p.read_text()!=text:p.write_text(text)
    if not (project/'check-runtime.py').is_file():raise ValueError('requires the preceding runtime source project')
    checked=json.loads((comparison/'comparison-result.json').read_text())
    if checked['status']!='match' or checked['component_id']!='math-support':raise ValueError('requires matching numeric comparison')
    write('bridges/math-support/bridge.c',AUTHOR['bridge']())
    write('common/math-state.h',(comparison/'inputs/source/math-state.h').read_text())
    write('common/math-runtime.c',(comparison/'inputs/adapters/runtime.c').read_text());write('common/math-runtime.h',AUTHOR['runtime_header']())
    cases=[dict(id=c['id'],arguments=['source',*c['arguments']],expected=c['observations']['original']) for c in checked['cases']]
    write('math-cases.json',json.dumps(cases,separators=(',',':'))+'\n')
    write('check-math.py','''import argparse,json,subprocess
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--runner',action='append',default=[])
a=p.parse_args();root=Path(__file__).resolve().parent
cases=json.loads((root/'math-cases.json').read_text())
for case in cases:
    ran=subprocess.run([*a.runner,str(root/'math'),*case['arguments']],capture_output=True,text=True,timeout=30)
    if ran.returncode:raise RuntimeError(case['id']+': '+ran.stderr[-2000:])
    if json.loads(ran.stdout)!=case['expected']:raise RuntimeError(case['id']+': numeric output differs from original x86 observations')
print(str(len(cases))+' numeric cases match retained original x86 observations')
''')
    marker='# Numeric consumer\n';base,found,tail=(project/'Makefile').read_text().partition(marker);suffix=''
    if found:
        _,separator,later=tail.partition('\n# ');suffix=separator+later
    write('Makefile',base.rstrip()+'\n\n'+marker+'''all: math
math: build/math-runtime.o build/math-support.o lifted/liblifted.a
\t$(CC) $(LDFLAGS) $^ -lm -o $@
build/math-runtime.o: common/math-runtime.c
\t@mkdir -p build
\t$(CC) $(CFLAGS) -DDX_STANDALONE -Icommon -MMD -MP -c $< -o $@
build/math-support.o: bridges/math-support/bridge.c
\t@mkdir -p build
\t$(CC) $(CFLAGS) -Icommon -Ilifted/components/math-support/sources/generated -Ilifted/components/math-support/sources/source -MMD -MP -c $< -o $@
'''+suffix)
    note='\nNumeric support: `python check-math.py` checks native-derived tables, projections, extreme angles and pan. The consumer links ordinary libm. AArch64 accepts `--runner /path/to/qemu-aarch64`.\n'
    current=(project/'README.md').read_text()
    if note not in current:write('README.md',current+note)

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for n in ('project','comparison'):p.add_argument(n,type=Path)
    a=p.parse_args();assemble(a.project.resolve(),a.comparison.resolve())
