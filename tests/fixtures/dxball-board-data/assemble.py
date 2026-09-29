"""Add native-checked board storage to the existing portable source project."""
import argparse
import importlib.util
import json
from pathlib import Path
import shutil

from spaghetti_extractor.candidate.source_export_bindings import render_source_service_bridges

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('board_preparation',HERE/'prepare.py')
preparation=importlib.util.module_from_spec(spec);spec.loader.exec_module(preparation)


def assemble(project,comparison):
    result=json.loads((comparison/'comparison-result.json').read_text())
    if result['status']!='match' or result['component_id']!='board-data':raise ValueError('requires matching board comparison')
    if not (project/'check-screen.py').is_file():raise ValueError('start from the score-screen source project')
    def write(name,text):
        path=project/name;path.parent.mkdir(parents=True,exist_ok=True)
        if not path.exists() or path.read_text()!=text:path.write_text(text)
    rendered=render_source_service_bridges(project/'lifted',bindings={'board-data':preparation.bridge_spec()})
    write('bridges/board-data/comparison-service-bridge.h',rendered['board-data'][0])
    write('bridges/board-data/bridge.c',preparation.bridge())
    write('common/board-runtime.h',preparation.runtime_header())
    write('common/board-state.h',(HERE/'board-state.h').read_text())
    write('common/boards-runtime.c',(HERE/'runtime.c').read_text())
    shutil.copyfile(comparison/'inputs/runtime/default.bds',project/'default.bds')
    write('boards-cases.json',json.dumps([dict(id=row['id'],arguments=row['arguments'],
        expected=row['observations']['original']) for row in result['cases']],indent=2)+'\n')
    write('check-boards.py','''import argparse,json,subprocess
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--runner',action='append',default=[])
a=p.parse_args();root=Path(__file__).resolve().parent;cases=json.loads((root/'boards-cases.json').read_text())
for case in cases:
    ran=subprocess.run([*a.runner,str(root/'boards'),'source',*case['arguments']],cwd=root,capture_output=True,text=True,timeout=30)
    if ran.returncode:raise RuntimeError(case['id']+': '+ran.stderr[-2000:])
    if json.loads(ran.stdout)!=case['expected']:raise RuntimeError(case['id']+': native observations differ')
print(str(len(cases))+' standalone board-data cases match original x86 observations')
''')
    marker='# Board data consumer\n';base=(project/'Makefile').read_text().split(marker)[0]
    write('Makefile',base+'\n'+marker+'''all: boards
boards: build/boards-runtime.o build/board-data.o lifted/liblifted.a
\t$(CC) $(LDFLAGS) build/boards-runtime.o build/board-data.o lifted/liblifted.a -o $@
build/boards-runtime.o: common/boards-runtime.c
\t@mkdir -p build
\t$(CC) $(CFLAGS) -DDX_STANDALONE -Icommon -MMD -MP -c $< -o $@
build/board-data.o: bridges/board-data/bridge.c bridges/board-data/comparison-service-bridge.h
\t@mkdir -p build
\t$(CC) $(CFLAGS) -Icommon -Ibridges/board-data -Ilifted/components/board-data/sources/generated -Ilifted/components/board-data/sources/source -Ilifted/components/board-data/sources/headers -MMD -MP -c $< -o $@
''')
    text=(project/'README.md').read_text().replace('Fifteen components','Sixteen components')
    paragraph='\nBoard storage adds collection load/save, current-board selection/storage and tile sprite mapping. Run `python check-boards.py`.\n'
    write('README.md',text if paragraph in text else text+paragraph)


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('project','comparison'):p.add_argument(name,type=Path)
    a=p.parse_args();assemble(a.project.resolve(),a.comparison.resolve())
