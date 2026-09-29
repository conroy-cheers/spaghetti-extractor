"""Add the checked file reader and shared file environment to a source project."""
import argparse
import json
from pathlib import Path
import re
import runpy
from spaghetti_extractor.candidate.source_export_bindings import render_source_service_bridges

HERE=Path(__file__).resolve().parent
AUTHOR=runpy.run_path(str(HERE/'prepare.py'))

def assemble(project,comparison):
    def write(name,text):
        p=project/name;p.parent.mkdir(parents=True,exist_ok=True)
        if not p.exists() or p.read_text()!=text:p.write_text(text)
    if not (project/'check-wave.py').is_file():raise ValueError('requires the preceding WAV source project')
    checked=json.loads((comparison/'comparison-result.json').read_text())
    if checked['status']!='match' or checked['component_id']!='file-reader':raise ValueError('requires matching reader comparison')
    rendered=render_source_service_bridges(project/'lifted',bindings={'file-reader':AUTHOR['bridge_spec']()})
    write('bridges/file-reader/comparison-service-bridge.h',rendered['file-reader'][0]);write('bridges/file-reader/bridge.c',AUTHOR['bridge']())
    for source in (comparison/'inputs/adapters').glob('spx-wine-*.c'):
        write('common/'+source.name,source.read_text())
    for name in ('spx-wine-test.h','spx-wine-test-internal.h','pe32-import-hook.h','spx-observation.h'):
        write('common/'+name,(comparison/'inputs/headers'/name).read_text())
    write('common/reader-state.h',(comparison/'inputs/source/reader-state.h').read_text())
    write('common/reader-runtime.c',(HERE/'runtime.c').read_text());write('common/reader-runtime.h',AUTHOR['runtime_header']())
    cases=[dict(id=c['id'],arguments=['source',*c['arguments']],expected=c['observations']['original']) for c in checked['cases']]
    write('reader-cases.json',json.dumps(cases,separators=(',',':'))+'\n')
    write('check-reader.py','''import argparse,json,subprocess
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--runner',action='append',default=[])
a=p.parse_args();root=Path(__file__).resolve().parent
cases=json.loads((root/'reader-cases.json').read_text())
for case in cases:
    ran=subprocess.run([*a.runner,str(root/'file-reader'),*case['arguments']],capture_output=True,text=True,timeout=30)
    if ran.returncode:raise RuntimeError(case['id']+': '+ran.stderr[-2000:])
    observed=json.loads(ran.stdout)
    if observed!=case['expected']:raise RuntimeError(case['id']+': '+json.dumps(dict(expected=case['expected'],observed=observed)))
print(str(len(cases))+' file reader cases match retained original x86 observations')
''')
    marker='# File reader consumer\n';base,found,tail=(project/'Makefile').read_text().partition(marker);suffix=''
    if found:
        _,separator,later=tail.partition('\n# ');suffix=separator+later
    # Refresh earlier consumers exported before backend modules became extensible.
    base=re.sub(r'(?:build/spx-wine-[a-z-]+\.o )+lifted/liblifted\.a',
        '$(patsubst common/%.c,build/%.o,$(wildcard common/spx-wine-*.c)) lifted/liblifted.a',base)
    rule=''
    if 'build/spx-wine-%.o:' not in base:rule='''build/spx-wine-%.o: common/spx-wine-%.c
\t@mkdir -p build
\t$(CC) $(CFLAGS) -Icommon -MMD -MP -c $< -o $@
'''
    write('Makefile',base.rstrip()+'\n\n'+marker+'''all: file-reader
file-reader: build/reader-runtime.o build/file-reader.o $(patsubst common/%.c,build/%.o,$(wildcard common/spx-wine-*.c)) lifted/liblifted.a
\t$(CC) $(LDFLAGS) $^ -o $@
build/reader-runtime.o: common/reader-runtime.c
\t@mkdir -p build
\t$(CC) $(CFLAGS) -DDX_STANDALONE -Icommon -MMD -MP -c $< -o $@
build/file-reader.o: bridges/file-reader/bridge.c bridges/file-reader/comparison-service-bridge.h
\t@mkdir -p build
\t$(CC) $(CFLAGS) -Icommon -Ibridges/file-reader -Ilifted/components/file-reader/sources/generated -Ilifted/components/file-reader/sources/source -Ilifted/components/file-reader/sources/headers -MMD -MP -c $< -o $@
'''+rule+suffix)
    note='\nFile reader: `python check-reader.py` exercises allocation/supplied-buffer contexts, fallback paths, short/failed reads and handle leaks through the shared Win32 environment. Use `--runner /path/to/qemu-aarch64` for AArch64.\n'
    current=(project/'README.md').read_text()
    if note not in current:write('README.md',current+note)

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for n in ('project','comparison'):p.add_argument(n,type=Path)
    a=p.parse_args();assemble(a.project.resolve(),a.comparison.resolve())
