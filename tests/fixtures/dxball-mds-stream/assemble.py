"""Integrate stream lifecycle with the preceding loader and shared platform consumers."""
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
    if not (project/'check-mds-loader.py').is_file():raise ValueError('requires the preceding MDS loader source project')
    checked=json.loads((comparison/'comparison-result.json').read_text())
    if checked['status']!='match' or checked['component_id']!='mds-stream':raise ValueError('requires matching stream comparison')
    rendered=render_source_service_bridges(project/'lifted',bindings={'mds-stream':AUTHOR['bridge_spec']()})
    write('bridges/mds-stream/comparison-service-bridge.h',rendered['mds-stream'][0]);write('bridges/mds-stream/bridge.c',AUTHOR['bridge']())
    for name in ('mds-stream-state.h','mds-loader-state.h','mds-state.h','mds-events-state.h'):write('common/'+name,(comparison/'inputs/source'/name).read_text())
    write('common/mds-stream-runtime.c',(comparison/'inputs/adapters/runtime.c').read_text())
    write('common/mds-stream-runtime.h',AUTHOR['runtime_header']())
    write('common/mds-transport.c',(comparison/'inputs/headers/mds-transport.c').read_text())
    write('common/loader-transport.c',(comparison/'inputs/headers/loader-transport.c').read_text())
    write('common/stream-transport.c',(comparison/'inputs/headers/stream-transport.c').read_text())
    for name in ('spx-wine-test.h','spx-wine-midi.c'):
        folder='headers' if name.endswith('.h') else 'adapters'
        write('common/'+name,(comparison/'inputs'/folder/name).read_text())
    for name in AUTHOR['ASSETS']:shutil.copyfile(comparison/'inputs/runtime'/name,project/name)
    cases=[dict(id=c['id'],arguments=['source',*c['arguments']],expected=c['observations']['original']) for c in checked['cases']]
    write('mds-stream-cases.json',json.dumps(cases,separators=(',',':'))+'\n')
    write('check-mds-stream.py','''import argparse,json,subprocess
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--runner',action='append',default=[])
a=p.parse_args();root=Path(__file__).resolve().parent
cases=json.loads((root/'mds-stream-cases.json').read_text())
for case in cases:
    ran=subprocess.run([*a.runner,str(root/'mds-stream'),*case['arguments']],cwd=root,capture_output=True,text=True,timeout=30)
    if ran.returncode:raise RuntimeError(case['id']+': '+ran.stderr[-2000:])
    observed=json.loads(ran.stdout)
    if observed!=case['expected']:raise RuntimeError(case['id']+': observations differ from retained original x86 execution')
print(str(len(cases))+' MDS stream cases match retained original x86 observations')
''')
    marker='# MDS stream consumer\n';base,found,tail=(project/'Makefile').read_text().partition(marker);suffix=''
    if found:
        _,separator,later=tail.partition('\n# ');suffix=separator+later
    write('Makefile',base.rstrip()+'\n\n'+marker+'''all: mds-stream
mds-stream: build/mds-stream-runtime.o build/mds-stream.o build/mds-loader.o build/mds-parser.o build/mds-events.o $(patsubst common/%.c,build/%.o,$(wildcard common/spx-wine-*.c)) lifted/liblifted.a
\t$(CC) $(LDFLAGS) $^ -o $@
build/mds-stream-runtime.o: common/mds-stream-runtime.c
\t@mkdir -p build
\t$(CC) $(CFLAGS) -DDX_STANDALONE -Icommon -MMD -MP -c $< -o $@
build/mds-stream.o: bridges/mds-stream/bridge.c bridges/mds-stream/comparison-service-bridge.h
\t@mkdir -p build
\t$(CC) $(CFLAGS) -Icommon -Ibridges/mds-stream -Ilifted/components/mds-stream/sources/generated -Ilifted/components/mds-stream/sources/source -Ilifted/components/mds-stream/sources/headers -MMD -MP -c $< -o $@
'''+suffix)
    note='\nMDS stream lifecycle: `python check-mds-stream.py` compares playback, completion, cleanup and all six music files using the selected loader, parser and event expander. AArch64 accepts `--runner /path/to/qemu-aarch64`.\n'
    current=(project/'README.md').read_text()
    if note not in current:write('README.md',current+note)

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('project','comparison'):p.add_argument(name,type=Path)
    a=p.parse_args();assemble(a.project.resolve(),a.comparison.resolve())
