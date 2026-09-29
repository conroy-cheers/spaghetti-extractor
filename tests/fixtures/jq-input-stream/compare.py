"""Bind an authored input-state workspace to the pinned native jq consumer."""
from pathlib import Path
import argparse
import json
import runpy

from spaghetti_extractor.components.comparison_environment import native_environment, native_adapter_headers
from spaghetti_extractor.components.comparison_original import native_entry_header
from spaghetti_extractor.components.comparison_package import prepare_comparison_package


def prepare(workspace, retained, output):
    here = Path(__file__).resolve().parent
    bindings = output.parent / 'native-inputs'
    bindings.mkdir(exist_ok=True)
    rows = json.loads((here / 'native-entries.json').read_text())
    hooks = ''
    for name, _, _, _, _, _, _, _, rva, end in rows:
        hooks += native_entry_header(
            original=retained / 'runtime/libjq-1.dll',
            expected_sha256='50d05ffd1f3cdbb5257f2cda429d9b920d95c091bb88a9d8bcdcb08ae9bacb1d',
            module='libjq-1.dll', entry_rva=rva, end_rva=end, installer='install_' + name,
            **({'additional_ranges': ((0x44c26, 0x44f46),)} if name == 'init' else {}))
    (bindings / 'native-entry.h').write_text(hooks)
    names = ('raw', 'raw-slurp', 'raw-early', 'raw-missing', 'json', 'json-slurp',
             'json-early', 'json-missing', 'json-bad', 'json-slurp-bad', 'raw-slurp-stdin')
    prepare_comparison_package(
        **runpy.run_path(str(workspace / 'prepare.py'))['source_inputs'](),
        **native_environment(retained),
        adapter_files={'driver.c': here / 'driver.c', 'entries.c': here / 'entries.c',
                       'windows-files.c': here.parent / 'portable-runtime/windows-files.c',
                       'allocation-observer.c': here.parent / 'jq-array-storage/allocation-observer.c'},
        include_files={**{p.name: p for p in (workspace / 'headers').iterdir()},
                       'entries.h': here / 'entries.h', 'native-entry.h': bindings / 'native-entry.h',
                       'allocation-observer.h': here.parent / 'jq-array-storage/allocation-observer.h',
                       **native_adapter_headers()},
        original_files=['runtime/libjq-1.dll'], oracle_kind='native-original',
        cases=[dict(id=name, arguments=[name]) for name in names],
        observation_fields=['contexts', 'allocation_lifetime'],
        assumptions=json.loads((workspace / 'assumptions.json').read_text()),
        scope='jq multi-file input: two independent states, raw/JSON/slurp, case lookup, EOF, errors, callback identity and early teardown.',
        output=output)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('workspace', 'retained', 'output'):
        parser.add_argument(name, type=Path)
    args = parser.parse_args()
    prepare(args.workspace.resolve(), args.retained.resolve(), args.output.resolve())
