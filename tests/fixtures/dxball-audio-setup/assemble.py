"""Add sound device setup and its connected bank consumer to a source project."""
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
    if not (project/'check-audio.py').is_file():raise ValueError('requires the preceding DX-Ball sound-bank source project')
    checked=json.loads((comparison/'comparison-result.json').read_text())
    if checked['status']!='match' or checked['component_id']!='audio-setup':raise ValueError('requires matching sound setup comparison')
    render=render_source_service_bridges(project/'lifted',bindings={'audio-setup':AUTHOR['bridge_spec']()})
    write('bridges/audio-setup/comparison-service-bridge.h',render['audio-setup'][0]);write('bridges/audio-setup/bridge.c',AUTHOR['bridge']())
    for p in (comparison/'inputs/source').glob('*.h'):write('common/'+p.name,p.read_text())
    write('common/bank-runtime.c',(comparison/'inputs/headers/bank-runtime.c').read_text())
    write('common/setup-runtime.c',(HERE/'runtime.c').read_text());write('common/setup-runtime.h',AUTHOR['runtime_header']())
    for role,names in [('adapters',tuple(p.name for p in sorted((comparison/'inputs/adapters').glob('spx-wine-*.c')))),
                       ('headers',('spx-wine-test.h','spx-wine-test-internal.h','pe32-import-hook.h','spx-observation.h'))]:
        for name in names:write('common/'+name,(comparison/'inputs'/role/name).read_text())
    cases=[dict(id=c['id'],arguments=['source',*c['arguments']],expected=c['observations']['original']) for c in checked['cases']]
    write('audio-setup-cases.json',json.dumps(cases,separators=(',',':'))+'\n')
    write('check-audio-setup.py','''import argparse,json,subprocess
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--runner',action='append',default=[])
a=p.parse_args();root=Path(__file__).resolve().parent
cases=json.loads((root/'audio-setup-cases.json').read_text())
for case in cases:
    ran=subprocess.run([*a.runner,str(root/'audio-setup'),*case['arguments']],capture_output=True,text=True,timeout=30)
    if ran.returncode:raise RuntimeError(case['id']+': '+ran.stderr[-2000:])
    observed=json.loads(ran.stdout)
    if observed!=case['expected']:raise RuntimeError(case['id']+': '+json.dumps(dict(expected=case['expected'],observed=observed)))
print(str(len(cases))+' audio setup cases match retained original x86 observations')
''')
    marker='# Sound device setup consumer\n';base,found,tail=(project/'Makefile').read_text().partition(marker);suffix=''
    if found:
        _,separator,later=tail.partition('\n# ');suffix=separator+later
    if 'build/spx-wine-%.o:' not in base:
        base+='\nbuild/spx-wine-%.o: common/spx-wine-%.c\n\t@mkdir -p build\n\t$(CC) $(CFLAGS) -Icommon -MMD -MP -c $< -o $@\n'
    write('Makefile',base.rstrip()+'\n\n'+marker+'''all: audio-setup
audio-setup: build/setup-runtime.o build/audio-setup.o build/audio-bank.o $(patsubst common/%.c,build/%.o,$(wildcard common/spx-wine-*.c)) lifted/liblifted.a
\t$(CC) $(LDFLAGS) $^ -o $@
build/setup-runtime.o: common/setup-runtime.c
\t@mkdir -p build
\t$(CC) $(CFLAGS) -DDX_STANDALONE -Icommon -MMD -MP -c $< -o $@
build/audio-setup.o: bridges/audio-setup/bridge.c bridges/audio-setup/comparison-service-bridge.h
\t@mkdir -p build
\t$(CC) $(CFLAGS) -Icommon -Ibridges/audio-setup -Ilifted/components/audio-setup/sources/generated -Ilifted/components/audio-setup/sources/source -Ilifted/components/audio-setup/sources/headers -MMD -MP -c $< -o $@
'''+suffix)
    note='\nSound device setup: `python check-audio-setup.py` executes initialization, retries, failure cleanup and refocus with the actual sound-bank C, without Wine or a sound device. It accepts `--runner /path/to/qemu-aarch64`. Native WAV loading and platform implementations remain separate work.\n'
    current=(project/'README.md').read_text()
    if note not in current:write('README.md',current+note)

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for n in ('project','comparison'):p.add_argument(n,type=Path)
    a=p.parse_args();assemble(a.project.resolve(),a.comparison.resolve())
