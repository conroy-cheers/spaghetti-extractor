"""Connect native-checked region C to the standalone editor and a local consumer."""
import argparse
import importlib.util
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('regions_preparation', HERE/'prepare.py')
preparation = importlib.util.module_from_spec(spec)
spec.loader.exec_module(preparation)


def assemble(project, comparison):
    result = json.loads((comparison/'comparison-result.json').read_text())
    if result['status'] != 'match' or result['component_id'] != 'hit-regions':
        raise ValueError('requires matching region comparison')
    if not (project/'check-damage.py').is_file():
        raise ValueError('start from the damage source project')
    def write(name, text):
        path = project/name
        path.parent.mkdir(parents=True, exist_ok=True)
        if not path.exists() or path.read_text() != text:
            path.write_text(text)
    write('bridges/hit-regions/bridge.c', preparation.bridge())
    for name, text in {'regions-state.h': (HERE/'regions-state.h').read_text(),
        'regions-runtime.h': preparation.runtime_header(), 'regions-runtime.c': (HERE/'runtime.c').read_text(),
        'editor-runtime.c': (HERE.parent/'dxball-board-editor/runtime.c').read_text()}.items():
        write('common/'+name, text)
    write('regions-cases.json', json.dumps([dict(id=row['id'], arguments=row['arguments'], expected=row['observations']['original'])
        for row in result['cases']], indent=2)+'\n')
    write('check-regions.py', '''import argparse,json,subprocess
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--runner',action='append',default=[])
a=p.parse_args();root=Path(__file__).resolve().parent;cases=json.loads((root/'regions-cases.json').read_text())
for case in cases:
    ran=subprocess.run([*a.runner,str(root/'regions'),'source',*case['arguments']],cwd=root,capture_output=True,text=True,timeout=30)
    if ran.returncode:raise RuntimeError(case['id']+': '+ran.stderr[-2000:])
    if json.loads(ran.stdout)!=case['expected']:raise RuntimeError(case['id']+': native observations differ')
print(str(len(cases))+' standalone region cases match original x86 observations')
''')
    text = (project/'Makefile').read_text()
    start = text.index('# Board editor consumer\n')
    end = text.index('# Board rendering consumer\n', start)
    editor = text[start:end]
    if 'build/hit-regions.o' not in editor:
        editor = editor.replace('build/editor-runtime.o build/board-editor.o', 'build/editor-runtime.o build/hit-regions.o build/board-editor.o')
        editor = editor.replace('-DDX_STANDALONE -Icommon', '-DDX_STANDALONE -DEDITOR_REGION_COMPONENT -Icommon')
    text = text[:start]+editor+text[end:]
    marker = '# Region consumer\n'
    if marker not in text:
        text += '\n'+marker+'''all: regions
regions: build/regions-runtime.o build/hit-regions.o lifted/liblifted.a
\t$(CC) $(LDFLAGS) build/regions-runtime.o build/hit-regions.o lifted/liblifted.a -o $@
build/regions-runtime.o: common/regions-runtime.c
\t@mkdir -p build
\t$(CC) $(CFLAGS) -DDX_STANDALONE -Icommon -MMD -MP -c $< -o $@
build/hit-regions.o: bridges/hit-regions/bridge.c
\t@mkdir -p build
\t$(CC) $(CFLAGS) -Icommon -Ilifted/components/hit-regions/sources/generated -Ilifted/components/hit-regions/sources/source -Ilifted/components/hit-regions/sources/headers -MMD -MP -c $< -o $@
'''
    write('Makefile', text)
    text = (project/'README.md').read_text().replace('Nineteen components', 'Twenty components')
    paragraph = '\nRegion reset/definition/lookup now serve the C editor through its existing borrowed table. Run `python check-regions.py` and `python check-editor.py`; neither needs the game UI or original binary.\n'
    write('README.md', text if paragraph in text else text+paragraph)


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('project', 'comparison'):
        p.add_argument(name, type=Path)
    a = p.parse_args()
    assemble(a.project.resolve(), a.comparison.resolve())
