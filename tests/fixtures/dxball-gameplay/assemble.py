"""Add the native-checked gameplay frame to the retained portable source project."""
import argparse
import importlib.util
import json
from pathlib import Path

from spaghetti_extractor.candidate.source_export_bindings import render_source_service_bridges

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('play_preparation',HERE/'prepare.py')
preparation=importlib.util.module_from_spec(spec);spec.loader.exec_module(preparation)


def assemble(project,comparison):
    result=json.loads((comparison/'comparison-result.json').read_text())
    if result['status']!='match' or result['component_id']!='gameplay-frame':raise ValueError('requires matching gameplay comparison')
    if not (project/'check-regions.py').is_file():raise ValueError('start from the region source project')
    def write(name,text):
        path=project/name;path.parent.mkdir(parents=True,exist_ok=True)
        if not path.exists() or path.read_text()!=text:path.write_text(text)
    rendered=render_source_service_bridges(project/'lifted',bindings={'gameplay-frame':preparation.bridge_spec()})
    write('bridges/gameplay-frame/comparison-service-bridge.h',rendered['gameplay-frame'][0])
    write('bridges/gameplay-frame/bridge.c',preparation.bridge())
    for name,text in {'play-state.h':(HERE/'play-state.h').read_text(),'play-runtime.h':preparation.runtime_header(),
        'play-runtime.c':(HERE/'runtime.c').read_text()}.items():write('common/'+name,text)
    write('play-cases.json',json.dumps([dict(id=row['id'],arguments=row['arguments'],expected=row['observations']['original'])
        for row in result['cases']],indent=2)+'\n')
    write('check-play.py','''import argparse,json,subprocess
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--runner',action='append',default=[])
a=p.parse_args();root=Path(__file__).resolve().parent;cases=json.loads((root/'play-cases.json').read_text())
for case in cases:
    ran=subprocess.run([*a.runner,str(root/'play'),'source',*case['arguments']],cwd=root,capture_output=True,text=True,timeout=30)
    if ran.returncode:raise RuntimeError(case['id']+': '+ran.stderr[-2000:])
    if json.loads(ran.stdout)!=case['expected']:raise RuntimeError(case['id']+': native observations differ')
print(str(len(cases))+' standalone gameplay frame cases match original x86 observations')
''')
    marker='# Gameplay frame consumer\n';base,found,old=(project/'Makefile').read_text().partition(marker)
    suffix=''
    if found:
        _,separator,later=old.partition('\n# ');suffix=separator+later
    write('Makefile',base+'\n'+marker+'''all: play
play: build/play-runtime.o build/gameplay-frame.o lifted/liblifted.a
\t$(CC) $(LDFLAGS) build/play-runtime.o build/gameplay-frame.o lifted/liblifted.a -o $@
build/play-runtime.o: common/play-runtime.c
\t@mkdir -p build
\t$(CC) $(CFLAGS) -DDX_STANDALONE -Icommon -MMD -MP -c $< -o $@
build/gameplay-frame.o: bridges/gameplay-frame/bridge.c bridges/gameplay-frame/comparison-service-bridge.h
\t@mkdir -p build
\t$(CC) $(CFLAGS) -Icommon -Ibridges/gameplay-frame -Ilifted/components/gameplay-frame/sources/generated -Ilifted/components/gameplay-frame/sources/source -Ilifted/components/gameplay-frame/sources/headers -MMD -MP -c $< -o $@
'''+suffix)
    text=(project/'README.md').read_text().replace('Twenty components','Twenty-one components')
    paragraph='\nGameplay frame sequencing adds shared lists, callback mutation, event disposal and velocity calculations. Run `python check-play.py` without the original executable or game UI. Helper bodies and platform services remain separate lifting work.\n'
    write('README.md',text if paragraph in text else text+paragraph)


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('project','comparison'):p.add_argument(name,type=Path)
    a=p.parse_args();assemble(a.project.resolve(),a.comparison.resolve())
