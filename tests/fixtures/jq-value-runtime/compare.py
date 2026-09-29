"""Bind the value-runtime module to retained native inputs without rebuilding a pilot."""
import argparse
import json
from pathlib import Path
import runpy

from cases import cases
from spaghetti_extractor.components.comparison_environment import native_environment, native_adapter_headers
from spaghetti_extractor.components.comparison_original import native_entry_header
from spaghetti_extractor.components.comparison_package import prepare_comparison_package


def prepare(workspace, retained, output):
    here = Path(__file__).resolve().parent
    bindings = output.parent / 'native-inputs'
    bindings.mkdir(exist_ok=True)
    rows = json.loads((here / 'native-entries.json').read_text())
    header = ''
    for row in rows:
        header += native_entry_header(original=retained / 'runtime/libjq-1.dll',
            expected_sha256='50d05ffd1f3cdbb5257f2cda429d9b920d95c091bb88a9d8bcdcb08ae9bacb1d',
            module='libjq-1.dll', entry_rva=row['entry_rva'], end_rva=row['end_rva'],
            installer='install_' + row['name'])
    header += 'static int install_entries(void) { return ' + ' && '.join(
        'install_' + row['name'] + '((void (*)(void))spx_entry_' + row['name'] + ')' for row in rows) + '; }\n'
    header += 'static int entries_intact(void) { return ' + ' && '.join(
        'install_' + row['name'] + '_intact()' for row in rows) + '; }\n'
    (bindings / 'native-entry.h').write_text(header)
    prepare_comparison_package(**runpy.run_path(str(workspace / 'prepare.py'))['source_inputs'](),
        **native_environment(retained),
        adapter_files={name: here / name for name in ('driver.c', 'entries.c', 'native-runtime.c')} | {
            'allocation-observer.c': here.parent / 'jq-array-storage/allocation-observer.c'},
        include_files={**{p.name: p for p in (workspace / 'headers').iterdir()},
            'entries.h': here / 'entries.h', 'native-entry.h': bindings / 'native-entry.h',
            'allocation-observer.h': here.parent / 'jq-array-storage/allocation-observer.h',
            **native_adapter_headers()},
        original_files=['runtime/libjq-1.dll'], oracle_kind='native-original', cases=cases(),
        observation_fields=['result', 'allocation_lifetime'],
        assumptions=json.loads((workspace / 'assumptions.json').read_text()),
        scope='jq strings, invalid values, object mutation and iteration, aliases and releases, with real parser/interpreter consumers.',
        output=output)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('workspace', 'retained', 'output'):
        parser.add_argument(name, type=Path)
    args = parser.parse_args()
    prepare(args.workspace.resolve(), args.retained.resolve(), args.output.resolve())
