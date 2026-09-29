"""Integrate checked parsing with the existing event consumer and shared backend."""
import argparse
import json
from pathlib import Path
import runpy
import shutil
from spaghetti_extractor.candidate.source_export_bindings import render_source_service_bridges

HERE=Path(__file__).resolve().parent
AUTHOR=runpy.run_path(str(HERE/'prepare.py'))

def assemble(project,comparison):
    def write(name,text):
        p=project/name;p.parent.mkdir(parents=True,exist_ok=True)
        if not p.exists() or p.read_text()!=text:p.write_text(text)
    if not (project/'check-mds-events.py').is_file():raise ValueError('requires the preceding MDS event source project')
    checked=json.loads((comparison/'comparison-result.json').read_text())
    if checked['status']!='match' or checked['component_id']!='mds-parser':raise ValueError('requires matching parser comparison')
    rendered=render_source_service_bridges(project/'lifted',bindings={'mds-parser':AUTHOR['bridge_spec']()})
    write('bridges/mds-parser/comparison-service-bridge.h',rendered['mds-parser'][0]);write('bridges/mds-parser/bridge.c',AUTHOR['bridge']())
    for name in ('mds-state.h','mds-events-state.h'):write('common/'+name,(comparison/'inputs/source'/name).read_text())
    write('common/mds-parser-runtime.c',(comparison/'inputs/adapters/runtime.c').read_text())
    write('common/mds-parser-runtime.h',AUTHOR['runtime_header']())
    write('common/mds-transport.c',(comparison/'inputs/headers/mds-transport.c').read_text())
    for name in AUTHOR['ASSETS']:shutil.copyfile(comparison/'inputs/runtime'/name,project/name)
    cases=[dict(id=c['id'],arguments=['source',*c['arguments']],expected=c['observations']['original']) for c in checked['cases']]
    write('mds-parser-cases.json',json.dumps(cases,separators=(',',':'))+'\n')
    write('check-mds-parser.py','''import argparse,json,subprocess
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--runner',action='append',default=[])
a=p.parse_args();root=Path(__file__).resolve().parent
cases=json.loads((root/'mds-parser-cases.json').read_text())
for case in cases:
    ran=subprocess.run([*a.runner,str(root/'mds-parser'),*case['arguments']],cwd=root,capture_output=True,text=True,timeout=30)
    if ran.returncode:raise RuntimeError(case['id']+': '+ran.stderr[-2000:])
    observed=json.loads(ran.stdout)
    if observed!=case['expected']:raise RuntimeError(case['id']+': observations differ from retained original x86 execution')
print(str(len(cases))+' MDS parser cases match retained original x86 observations')
''')
    marker='# MDS parser consumer\n';base,found,tail=(project/'Makefile').read_text().partition(marker);suffix=''
    if found:
        _,separator,later=tail.partition('\n# ');suffix=separator+later
    write('Makefile',base.rstrip()+'\n\n'+marker+'''all: mds-parser
mds-parser: build/mds-parser-runtime.o build/mds-parser.o build/mds-events.o $(patsubst common/%.c,build/%.o,$(wildcard common/spx-wine-*.c)) lifted/liblifted.a
\t$(CC) $(LDFLAGS) $^ -o $@
build/mds-parser-runtime.o: common/mds-parser-runtime.c
\t@mkdir -p build
\t$(CC) $(CFLAGS) -DDX_STANDALONE -Icommon -MMD -MP -c $< -o $@
build/mds-parser.o: bridges/mds-parser/bridge.c bridges/mds-parser/comparison-service-bridge.h
\t@mkdir -p build
\t$(CC) $(CFLAGS) -Icommon -Ibridges/mds-parser -Ilifted/components/mds-parser/sources/generated -Ilifted/components/mds-parser/sources/source -Ilifted/components/mds-parser/sources/headers -MMD -MP -c $< -o $@
'''+suffix)
    note='\nMDS container parser: `python check-mds-parser.py` compares allocation history, partial header updates, cleanup effects and all six music files using the selected event expander. AArch64 accepts `--runner /path/to/qemu-aarch64`.\n'
    current=(project/'README.md').read_text()
    if note not in current:write('README.md',current+note)

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('project','comparison'):p.add_argument(name,type=Path)
    a=p.parse_args();assemble(a.project.resolve(),a.comparison.resolve())
