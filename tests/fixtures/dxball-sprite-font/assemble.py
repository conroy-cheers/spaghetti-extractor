"""Assemble the exported font/cleanup network as a portable source consumer."""
import argparse
import importlib.util
import json
from pathlib import Path

from spaghetti_extractor.candidate.source_export_bindings import render_source_service_bridges
from spaghetti_extractor.components.comparison_environment import observation_headers
from prepare import CLEANUP, HERE, OPERATIONS, bridge, bridge_spec, cleanup


def assemble(project, comparison):
    def write(name, content):
        path = project/name; path.parent.mkdir(parents=True, exist_ok=True)
        if not path.exists() or path.read_text() != content: path.write_text(content)
    bindings = {'cleanup-'+name: dict(adapters={key: dict(symbol='trial_'+key, kind='portable',
        context=True, outcomes={'return': None}) for key in names}, transports={}, native_symbol='bridge_'+name)
        for name, names in cleanup.SERVICES.items()}
    bindings.update({'font-'+unit: bridge_spec(unit) for unit in OPERATIONS})
    result = json.loads((comparison/'comparison-result.json').read_text())
    with_assets = result['component_id'] == 'sprite-loader'
    if result['status'] != 'match' or result['component_id'] not in ('font-render', 'sprite-loader'):
        raise ValueError('needs matching connected font/asset evidence')
    if with_assets:
        spec = importlib.util.spec_from_file_location('asset_preparation', HERE/'prepare-assets.py')
        asset_preparation = importlib.util.module_from_spec(spec); spec.loader.exec_module(asset_preparation)
        bindings['sprite-loader'] = asset_preparation.bridge_spec()
    rendered = render_source_service_bridges(project/'lifted', bindings=bindings)
    for identity in bindings:
        family, unit = identity.split('-')
        write('bridges/'+identity+'/comparison-service-bridge.h', rendered[identity][0])
        write('bridges/'+identity+'/bridge.c', cleanup.bridge(unit) if family == 'cleanup'
              else bridge(unit) if family == 'font' else asset_preparation.bridge())
    for name in ('runtime.h', 'cleanup-state.h'): write('common/'+name, (CLEANUP/name).read_text())
    write('common/cleanup-runtime.c', (CLEANUP/'runtime.c').read_text())
    for name in ('font-runtime.c', 'font-runtime.h', 'font-state.h'): write('common/'+name, (HERE/name).read_text())
    write('common/case-unit.h', '#define DX_UNIT 2\n#define FONT_UNIT 1\n')
    for name, path in observation_headers().items(): write('common/'+name, path.read_text())
    if with_assets:
        for name in ('asset-runtime.c', 'asset-runtime.h', 'asset-state.h'): write('common/'+name, (HERE/name).read_text())
        for name in ('Sysfont.sbk', 'Sfont.sbk', 'Thefont.sbk'):
            (project/name).write_bytes((comparison/'inputs/runtime'/name).read_bytes())
    write('cases.json', json.dumps([dict(id=row['id'], arguments=row['arguments'], expected=row['observations']['original'])
                                   for row in result['cases']], indent=2)+'\n')
    objects = ['build/runtime.o']+['build/'+identity+'.o' for identity in bindings]
    rules = []
    for identity in bindings:
        base = 'lifted/components/'+identity+'/sources/'
        includes = ' '.join('-I'+base+d for d in ('generated', 'source', 'headers'))
        rules.append(f'build/{identity}.o: bridges/{identity}/bridge.c bridges/{identity}/comparison-service-bridge.h\n'
            '\t@mkdir -p build\n'
            f'\t$(CC) $(CFLAGS) -Icommon -Ibridges/{identity} {includes} -MMD -MP -c $< -o $@\n')
    write('Makefile', '\n'.join([
        'CC ?= cc\nAR ?= ar\nCFLAGS ?= -O2 -std=c11 -Wall -Wextra -Werror\n',
        '.PHONY: all FORCE\nall: font\nFORCE:\n',
        'lifted/liblifted.a: FORCE\n\t$(MAKE) -C lifted CC="$(CC)" AR="$(AR)" CFLAGS="$(CFLAGS)"\n',
        'font: '+' '.join(objects)+' lifted/liblifted.a\n\t$(CC) $(LDFLAGS) '+' '.join(objects)+' lifted/liblifted.a -o $@\n',
        'build/runtime.o: common/'+('asset-runtime.c' if with_assets else 'font-runtime.c')+'\n\t@mkdir -p build\n'
        '\t$(CC) $(CFLAGS) -DDX_STANDALONE -Icommon -MMD -MP -c $< -o $@\n', *rules, '-include build/*.d\n']))
    write('check.py', '''import argparse,json,subprocess
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--runner',action='append',default=[])
a=p.parse_args();root=Path(__file__).resolve().parent;cases=json.loads((root/'cases.json').read_text())
for case in cases:
    ran=subprocess.run([*a.runner,str(root/'font'),'source',*case['arguments']],cwd=root,capture_output=True,text=True,timeout=30)
    if ran.returncode: raise RuntimeError(case['id']+': '+ran.stderr[-2000:])
    if json.loads(ran.stdout)!=case['expected']: raise RuntimeError(case['id']+': native observations differ')
print(str(len(cases))+' standalone cases match original x86 observations')
''')
    write('README.md', '# DX-Ball sprite font source consumer\n\nRun `make` and `python check.py`. '
        'CC/AR can select another architecture. '+str(len(bindings))+' connected components are compiled. '
        'Drawing and lifetime services are controlled; this is not the complete game.\n')


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__); p.add_argument('project', type=Path); p.add_argument('comparison', type=Path)
    a = p.parse_args(); assemble(a.project.resolve(), a.comparison.resolve())
