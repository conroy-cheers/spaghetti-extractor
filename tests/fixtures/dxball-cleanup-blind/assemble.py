"""Assemble this controlled source consumer using existing service bindings.

The delivered Makefile/check.py need only a C toolchain/Python standard library.
Regenerating service bindings uses the installed toolkit, as candidate apply does.
"""
import argparse
import json
from pathlib import Path

from spaghetti_extractor.candidate.source_export_bindings import render_source_service_bridges
from spaghetti_extractor.components.comparison_environment import observation_headers

from prepare import SERVICES, bridge

HERE = Path(__file__).resolve().parent


def assemble(project, comparison):
    def write(name, content):
        path = project/name; path.parent.mkdir(parents=True, exist_ok=True)
        if not path.exists() or path.read_text() != content: path.write_text(content)
    bindings = {'cleanup-'+name: dict(adapters={key: dict(symbol='trial_'+key, kind='portable',
        context=True, outcomes={'return': None}) for key in names}, transports={}, native_symbol='bridge_'+name)
        for name, names in SERVICES.items()}
    rendered = render_source_service_bridges(project/'lifted', bindings=bindings)
    for name in SERVICES:
        write('bridges/'+name+'/comparison-service-bridge.h', rendered['cleanup-'+name][0])
        write('bridges/'+name+'/bridge.c', bridge(name))
    for name in ('runtime.c', 'runtime.h', 'cleanup-state.h'):
        write('common/'+name, (HERE/name).read_text())
    write('common/case-unit.h', '#define DX_UNIT 2\n')
    for name, path in observation_headers().items(): write('common/'+name, path.read_text())
    result = json.loads((comparison/'comparison-result.json').read_text())
    if result['status'] != 'match' or result['component_id'] != 'cleanup-clear':
        raise ValueError('needs a matching connected cleanup comparison')
    write('cases.json', json.dumps([dict(id=row['id'], arguments=row['arguments'],
        expected=row['observations']['original']) for row in result['cases']], indent=2)+'\n')
    objects = ['build/runtime.o']+['build/'+name+'.o' for name in SERVICES]
    rules = []
    for name in SERVICES:
        base = 'lifted/components/cleanup-'+name+'/sources/'
        includes = ' '.join('-I'+base+d for d in ('generated', 'source', 'headers'))
        rules.append(f'build/{name}.o: bridges/{name}/bridge.c bridges/{name}/comparison-service-bridge.h common/runtime.h common/cleanup-state.h\n'
            '\t@mkdir -p build\n'
            f'\t$(CC) $(CFLAGS) -Icommon -Ibridges/{name} {includes} -MMD -MP -c $< -o $@\n')
    write('Makefile', '\n'.join([
        'CC ?= cc\nAR ?= ar\nCFLAGS ?= -O2 -std=c11 -Wall -Wextra -Werror\n',
        '.PHONY: all FORCE\nall: cleanup\nFORCE:\n',
        'lifted/liblifted.a: FORCE\n\t$(MAKE) -C lifted CC="$(CC)" AR="$(AR)" CFLAGS="$(CFLAGS)"\n',
        'cleanup: '+' '.join(objects)+' lifted/liblifted.a\n\t$(CC) $(LDFLAGS) '+' '.join(objects)+' lifted/liblifted.a -o $@\n',
        'build/runtime.o: common/runtime.c common/runtime.h common/cleanup-state.h common/spx-observation.h common/case-unit.h\n'
        '\t@mkdir -p build\n\t$(CC) $(CFLAGS) -DDX_STANDALONE -Icommon -MMD -MP -c $< -o $@\n',
        *rules, '-include build/*.d\n']))
    write('check.py', '''"""Compare the standalone source consumer with retained native observations."""
import argparse,json,subprocess
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--runner', action='append', default=[])
a=p.parse_args(); root=Path(__file__).resolve().parent
cases=json.loads((root/'cases.json').read_text())
for case in cases:
    ran=subprocess.run([*a.runner,str(root/'cleanup'),'source',*case['arguments']],capture_output=True,text=True,timeout=30)
    if ran.returncode: raise RuntimeError(case['id']+': '+ran.stderr[-2000:])
    if json.loads(ran.stdout)!=case['expected']: raise RuntimeError(case['id']+': native observation differs')
print(str(len(cases))+' standalone cases match original x86 observations')
''')
    write('README.md', '# Source-blind DX-Ball cleanup consumer\n\n'
        'Run `make` and `python check.py`. CC/AR can select another architecture.\n'
        'This is a standalone controlled subsystem consumer, not the complete game.\n'
        'Release/free are instrumented environment services. The three operation\n'
        'bodies were authored from the PE32 binary without original source.\n'
        'cases.json retains finite original-x86 observations; passing them is\n'
        'practical evidence, not universal equivalence.\n')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('project', type=Path); parser.add_argument('comparison', type=Path)
    args = parser.parse_args(); assemble(args.project.resolve(), args.comparison.resolve())
