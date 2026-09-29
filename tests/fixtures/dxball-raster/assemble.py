"""Add the raster consumer and refresh the shared Wine test resources."""
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
    if not (project/'check-math.py').is_file():raise ValueError('requires preceding numeric source project')
    checked=json.loads((comparison/'comparison-result.json').read_text())
    if checked['status']!='match' or checked['component_id']!='raster-drawing':raise ValueError('requires matching raster comparison')
    rendered=render_source_service_bridges(project/'lifted',bindings={'raster-drawing':AUTHOR['bridge_spec']()})
    write('bridges/raster-drawing/comparison-service-bridge.h',rendered['raster-drawing'][0])
    write('bridges/raster-drawing/bridge.c',AUTHOR['bridge']())
    write('common/raster-runtime.c',(comparison/'inputs/adapters/runtime.c').read_text());write('common/raster-runtime.h',AUTHOR['runtime_header']())
    for folder in ('adapters','headers'):
        for p in (comparison/'inputs'/folder).glob('spx-wine-*'):write('common/'+p.name,p.read_text())
    for name in ('spx-observation.h','pe32-import-hook.h'):
        write('common/'+name,(comparison/'inputs/headers'/name).read_text())
    cases=[dict(id=c['id'],arguments=['source',*c['arguments']],expected=c['observations']['original']) for c in checked['cases']]
    write('raster-cases.json',json.dumps(cases,separators=(',',':'))+'\n')
    write('check-raster.py','''import argparse,json,subprocess
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--runner',action='append',default=[])
a=p.parse_args();root=Path(__file__).resolve().parent
cases=json.loads((root/'raster-cases.json').read_text())
for case in cases:
    ran=subprocess.run([*a.runner,str(root/'raster'),*case['arguments']],capture_output=True,text=True,timeout=30)
    if ran.returncode:raise RuntimeError(case['id']+': '+ran.stderr[-2000:])
    if json.loads(ran.stdout)!=case['expected']:raise RuntimeError(case['id']+': pixels or DirectDraw observations differ from original x86')
print(str(len(cases))+' raster cases match retained original x86 observations')
''')
    marker='# Raster consumer\n';base,found,tail=(project/'Makefile').read_text().partition(marker);suffix=''
    if found:
        _,separator,later=tail.partition('\n# ');suffix=separator+later
    write('Makefile',base.rstrip()+'\n\n'+marker+'''all: raster
raster: build/raster-runtime.o build/raster-drawing.o $(patsubst common/%.c,build/%.o,$(wildcard common/spx-wine-*.c)) lifted/liblifted.a
\t$(CC) $(LDFLAGS) $^ -o $@
build/raster-runtime.o: common/raster-runtime.c
\t@mkdir -p build
\t$(CC) $(CFLAGS) -DDX_STANDALONE -Icommon -MMD -MP -c $< -o $@
build/raster-drawing.o: bridges/raster-drawing/bridge.c bridges/raster-drawing/comparison-service-bridge.h
\t@mkdir -p build
\t$(CC) $(CFLAGS) -Icommon -Ibridges/raster-drawing -Ilifted/components/raster-drawing/sources/generated -Ilifted/components/raster-drawing/sources/source -MMD -MP -c $< -o $@
'''+suffix)
    note='\nRaster support: `python check-raster.py` checks full surface storage and shared DirectDraw interactions. The shared environment refresh also requires the existing audio/setup/WAV/reader and MDS consumers to be rebuilt and checked. AArch64 accepts `--runner /path/to/qemu-aarch64`.\n'
    current=(project/'README.md').read_text()
    if note not in current:write('README.md',current+note)

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for n in ('project','comparison'):p.add_argument(n,type=Path)
    a=p.parse_args();assemble(a.project.resolve(),a.comparison.resolve())
