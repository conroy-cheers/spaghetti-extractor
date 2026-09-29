"""Integrate the music controller into the preceding standalone source selection."""
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
    if not (project/'check-reader.py').is_file():raise ValueError('requires the preceding reader source project')
    checked=json.loads((comparison/'comparison-result.json').read_text())
    if checked['status']!='match' or checked['component_id']!='music-control':raise ValueError('requires matching music controller comparison')
    rendered=render_source_service_bridges(project/'lifted',bindings={'music-control':AUTHOR['bridge_spec']()})
    write('bridges/music-control/comparison-service-bridge.h',rendered['music-control'][0]);write('bridges/music-control/bridge.c',AUTHOR['bridge']())
    write('common/music-state.h',(comparison/'inputs/source/music-state.h').read_text())
    write('common/music-runtime.c',(comparison/'inputs/adapters/runtime.c').read_text());write('common/music-runtime.h',AUTHOR['runtime_header']())
    cases=[dict(id=c['id'],arguments=['source',*c['arguments']],expected=c['observations']['original']) for c in checked['cases']]
    write('music-cases.json',json.dumps(cases,separators=(',',':'))+'\n')
    write('check-music.py','''import argparse,json,subprocess
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--runner',action='append',default=[])
a=p.parse_args();root=Path(__file__).resolve().parent
cases=json.loads((root/'music-cases.json').read_text())
for case in cases:
    ran=subprocess.run([*a.runner,str(root/'music'),*case['arguments']],capture_output=True,text=True,timeout=30)
    if ran.returncode:raise RuntimeError(case['id']+': '+ran.stderr[-2000:])
    observed=json.loads(ran.stdout)
    if observed!=case['expected']:raise RuntimeError(case['id']+': '+json.dumps(dict(expected=case['expected'],observed=observed)))
print(str(len(cases))+' music-controller cases match retained original x86 observations')
''')
    marker='# Music controller consumer\n';base=(project/'Makefile').read_text().split(marker)[0]
    write('Makefile',base.rstrip()+'\n\n'+marker+'''all: music
music: build/music-runtime.o build/music-control.o lifted/liblifted.a
\t$(CC) $(LDFLAGS) $^ -o $@
build/music-runtime.o: common/music-runtime.c
\t@mkdir -p build
\t$(CC) $(CFLAGS) -DDX_STANDALONE -Icommon -MMD -MP -c $< -o $@
build/music-control.o: bridges/music-control/bridge.c bridges/music-control/comparison-service-bridge.h
\t@mkdir -p build
\t$(CC) $(CFLAGS) -Icommon -Ibridges/music-control -Ilifted/components/music-control/sources/generated -Ilifted/components/music-control/sources/source -Ilifted/components/music-control/sources/headers -MMD -MP -c $< -o $@
''')
    note='\nMusic controller: `python check-music.py` exercises application record ownership, library outcomes, cleanup and callback-sensitive state. It does not emulate WinMM streaming. AArch64 accepts `--runner /path/to/qemu-aarch64`.\n'
    current=(project/'README.md').read_text()
    if note not in current:write('README.md',current+note)

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for n in ('project','comparison'):p.add_argument(n,type=Path)
    a=p.parse_args();assemble(a.project.resolve(),a.comparison.resolve())
