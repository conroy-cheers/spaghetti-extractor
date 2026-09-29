"""Integrate the independently executable WAV component into a source project."""
import argparse
import json
from pathlib import Path
import runpy
from spaghetti_extractor.candidate.source_export_bindings import render_source_service_bridges

HERE=Path(__file__).resolve().parent
AUTHOR=runpy.run_path(str(HERE/'prepare.py'))

def assemble(project,comparison):
    def write(name,text):
        path=project/name;path.parent.mkdir(parents=True,exist_ok=True)
        if not path.exists() or path.read_text()!=text:path.write_text(text)
    if not (project/'check-audio-setup.py').is_file():raise ValueError('requires the sound-setup source project')
    checked=json.loads((comparison/'comparison-result.json').read_text())
    if checked['status']!='match' or checked['component_id']!='wave-loader':raise ValueError('requires matching WAV comparison')
    rendered=render_source_service_bridges(project/'lifted',bindings={'wave-loader':AUTHOR['bridge_spec']()})
    write('bridges/wave-loader/comparison-service-bridge.h',rendered['wave-loader'][0]);write('bridges/wave-loader/bridge.c',AUTHOR['bridge']())
    for p in (comparison/'inputs/source').glob('*.h'):write('common/'+p.name,p.read_text())
    write('common/wave-bank-runtime.c',(comparison/'inputs/headers/bank-runtime.c').read_text())
    write('common/wave-runtime.c',(comparison/'inputs/adapters/runtime.c').read_text().replace('"bank-runtime.c"','"wave-bank-runtime.c"'))
    write('common/wave-runtime.h',AUTHOR['runtime_header']())
    cases=[dict(id=c['id'],arguments=['source',*c['arguments']],expected=c['observations']['original']) for c in checked['cases']]
    write('wave-cases.json',json.dumps(cases,separators=(',',':'))+'\n')
    write('check-wave.py','''import argparse,json,subprocess
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--runner',action='append',default=[])
a=p.parse_args();root=Path(__file__).resolve().parent
cases=json.loads((root/'wave-cases.json').read_text())
for case in cases:
    ran=subprocess.run([*a.runner,str(root/'wave'),*case['arguments']],capture_output=True,text=True,timeout=30)
    if ran.returncode:raise RuntimeError(case['id']+': '+ran.stderr[-2000:])
    observed=json.loads(ran.stdout)
    if observed!=case['expected']:raise RuntimeError(case['id']+': '+json.dumps(dict(expected=case['expected'],observed=observed)))
print(str(len(cases))+' WAV cases match retained original x86 observations')
''')
    marker='# WAV loader consumer\n';base,found,tail=(project/'Makefile').read_text().partition(marker);suffix=''
    if found:
        _,separator,later=tail.partition('\n# ');suffix=separator+later
    if 'build/spx-wine-%.o:' not in base:
        base+='\nbuild/spx-wine-%.o: common/spx-wine-%.c\n\t@mkdir -p build\n\t$(CC) $(CFLAGS) -Icommon -MMD -MP -c $< -o $@\n'
    write('Makefile',base.rstrip()+'\n\n'+marker+'''all: wave
wave: build/wave-runtime.o build/wave-loader.o build/audio-bank.o $(patsubst common/%.c,build/%.o,$(wildcard common/spx-wine-*.c)) lifted/liblifted.a
\t$(CC) $(LDFLAGS) $^ -o $@
build/wave-runtime.o: common/wave-runtime.c
\t@mkdir -p build
\t$(CC) $(CFLAGS) -DDX_STANDALONE -Icommon -MMD -MP -c $< -o $@
build/wave-loader.o: bridges/wave-loader/bridge.c bridges/wave-loader/comparison-service-bridge.h
\t@mkdir -p build
\t$(CC) $(CFLAGS) -Icommon -Ibridges/wave-loader -Ilifted/components/wave-loader/sources/generated -Ilifted/components/wave-loader/sources/source -Ilifted/components/wave-loader/sources/headers -MMD -MP -c $< -o $@
'''+suffix)
    note='\nWAV loading: `python check-wave.py` compares parsing, allocation, shared-bank interactions, failures and buffer bytes with retained x86 observations. AArch64 accepts `--runner /path/to/qemu-aarch64`. Native file loading and a portable platform implementation remain separate work.\n'
    current=(project/'README.md').read_text()
    if note not in current:write('README.md',current+note)

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for n in ('project','comparison'):p.add_argument(n,type=Path)
    a=p.parse_args();assemble(a.project.resolve(),a.comparison.resolve())
