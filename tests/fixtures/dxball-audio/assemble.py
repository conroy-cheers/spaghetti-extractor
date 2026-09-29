"""Add the independently executable audio bank to a DX-Ball source project."""
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
    if not (project/'check-display.py').is_file():raise ValueError('requires the existing DX-Ball source project')
    checked=json.loads((comparison/'comparison-result.json').read_text())
    if checked['status']!='match' or checked['component_id']!='audio-bank':raise ValueError('requires matching audio bank comparison')
    render=render_source_service_bridges(project/'lifted',bindings={'audio-bank':AUTHOR['bridge_spec']()})
    write('bridges/audio-bank/comparison-service-bridge.h',render['audio-bank'][0])
    write('bridges/audio-bank/bridge.c',AUTHOR['bridge']())
    write('common/audio-state.h',(HERE/'audio-state.h').read_text())
    write('common/audio-runtime.c',(HERE/'runtime.c').read_text())
    write('common/audio-runtime.h',AUTHOR['runtime_header']())
    for role,names in [('adapters',tuple(p.name for p in sorted((comparison/'inputs/adapters').glob('spx-wine-*.c')))),
                       ('headers',('spx-wine-test.h','spx-wine-test-internal.h','pe32-import-hook.h','spx-observation.h'))]:
        for name in names:write('common/'+name,(comparison/'inputs'/role/name).read_text())
    cases=[dict(id=c['id'],arguments=['source',*c['arguments']],expected=c['observations']['original']) for c in checked['cases']]
    write('audio-cases.json',json.dumps(cases,separators=(',',':'))+'\n')
    write('check-audio.py','''import argparse,json,subprocess
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--runner',action='append',default=[])
a=p.parse_args();root=Path(__file__).resolve().parent
cases=json.loads((root/'audio-cases.json').read_text())
for case in cases:
    ran=subprocess.run([*a.runner,str(root/'audio'),*case['arguments']],capture_output=True,text=True,timeout=30)
    if ran.returncode:raise RuntimeError(case['id']+': '+ran.stderr[-2000:])
    observed=json.loads(ran.stdout)
    if observed!=case['expected']:raise RuntimeError(case['id']+': '+json.dumps(dict(expected=case['expected'],observed=observed)))
print(str(len(cases))+' audio bank cases match retained original x86 observations')
''')
    marker='# Audio bank consumer\n';base,found,tail=(project/'Makefile').read_text().partition(marker)
    suffix=''
    if found:
        _,separator,later=tail.partition('\n# ');suffix=separator+later
    write('Makefile',base.rstrip()+'\n\n'+marker+'''all: audio
audio: build/audio-runtime.o build/audio-bank.o $(patsubst common/%.c,build/%.o,$(wildcard common/spx-wine-*.c)) lifted/liblifted.a
\t$(CC) $(LDFLAGS) $^ -o $@
build/spx-wine-%.o: common/spx-wine-%.c
\t@mkdir -p build
\t$(CC) $(CFLAGS) -Icommon -MMD -MP -c $< -o $@
build/audio-runtime.o: common/audio-runtime.c
\t@mkdir -p build
\t$(CC) $(CFLAGS) -DDX_STANDALONE -Icommon -MMD -MP -c $< -o $@
build/audio-bank.o: bridges/audio-bank/bridge.c bridges/audio-bank/comparison-service-bridge.h
\t@mkdir -p build
\t$(CC) $(CFLAGS) -Icommon -Ibridges/audio-bank -Ilifted/components/audio-bank/sources/generated -Ilifted/components/audio-bank/sources/source -Ilifted/components/audio-bank/sources/headers -MMD -MP -c $< -o $@
'''+suffix)
    note='\nAudio bank: `python check-audio.py` executes playback, recovery, callbacks and resource lifetime without Wine or the original image. Use `--runner /path/to/qemu-aarch64` for an AArch64 build. Platform operations are controlled services; device creation and sample loading remain neighboring work.\n'
    current=(project/'README.md').read_text()
    if note not in current:write('README.md',current+note)

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for n in ('project','comparison'):p.add_argument(n,type=Path)
    a=p.parse_args();assemble(a.project.resolve(),a.comparison.resolve())
