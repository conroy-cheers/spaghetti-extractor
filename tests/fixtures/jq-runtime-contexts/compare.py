"""Compare live context state and teardown with retained native inputs."""
import argparse
import json
from pathlib import Path
import runpy

from spaghetti_extractor.components.comparison_environment import native_environment, native_adapter_headers
from spaghetti_extractor.components.comparison_original import native_entry_header
from spaghetti_extractor.components.comparison_package import prepare_comparison_package


def prepare(workspace, retained, pthread_library, output):
    here = Path(__file__).resolve().parent
    bindings = output.parent / 'native-inputs'
    bindings.mkdir(exist_ok=True)
    rows = json.loads((here / 'native-entries.json').read_text())
    header = ''
    for row in rows:
        header += native_entry_header(original=retained / 'runtime/libjq-1.dll',
            expected_sha256='50d05ffd1f3cdbb5257f2cda429d9b920d95c091bb88a9d8bcdcb08ae9bacb1d',
            module='libjq-1.dll', entry_rva=row['entry_rva'], end_rva=row['end_rva'],
            additional_ranges=row['additional_ranges'], installer='install_' + row['name'])
    header += 'static int install_entries(void) { return ' + ' && '.join(
        'install_' + row['name'] + '((void (*)(void))spx_entry_' + row['name'] + ')' for row in rows) + '; }\n'
    header += 'static int entries_intact(void) { return ' + ' && '.join(
        'install_' + row['name'] + '_intact()' for row in rows) + '; }\n'
    (bindings / 'native-entry.h').write_text(header)
    observer = (here.parent / 'jq-array-storage/allocation-observer.c').read_text()
    assert observer.count('    original_free(p);') == 1
    observer = observer.replace('    original_free(p);',
        '    original_free(p);\n    if (p) context_observer_release();')
    observer = 'void context_observer_release(void);\n' + observer + '''
void *spx_context_malloc(size_t size) { return observed_malloc(size); }
'''
    (bindings / 'allocation-observer.c').write_text(observer)
    environment = native_environment(retained)
    environment['link_files']['libwinpthread.dll.a'] = pthread_library
    prepare_comparison_package(**runpy.run_path(str(workspace / 'prepare.py'))['source_inputs'](),
        **environment,
        adapter_files={name: here / name for name in ('driver.c', 'entries.c', 'native-runtime.c', 'entropy.c')} | {
            'allocation-observer.c': bindings / 'allocation-observer.c'},
        include_files={**{p.name: p for p in (workspace / 'headers').iterdir()},
            'entries.h': here / 'entries.h', 'native-entry.h': bindings / 'native-entry.h',
            'allocation-observer.h': here.parent / 'jq-array-storage/allocation-observer.h',
            **native_adapter_headers()},
        original_files=['runtime/libjq-1.dll'], oracle_kind='native-original',
        cases=[dict(id=scenario + '-' + str(mode), arguments=[scenario, str(mode)])
            for scenario in ('contexts', 'thread', 'explicit') for mode in range(4)],
        observation_fields=['events'],
        assumptions=json.loads((workspace / 'assumptions.json').read_text()),
        scope='jq live decimal/dtoa state, real consumers, once-only seed interactions, worker and complete process cleanup.',
        output=output)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('workspace', 'retained', 'pthread_library', 'output'):
        parser.add_argument(name, type=Path)
    args = parser.parse_args()
    prepare(args.workspace.resolve(), args.retained.resolve(), args.pthread_library.resolve(), args.output.resolve())
