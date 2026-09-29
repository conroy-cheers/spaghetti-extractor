"""Use normal PE program execution with the whole old test-runner body disabled."""
import argparse
import json
from pathlib import Path
import runpy

from cases import cases, files
from spaghetti_extractor.components.comparison_environment import native_environment, native_adapter_headers
from spaghetti_extractor.components.comparison_original import native_entry_header
from spaghetti_extractor.components.comparison_package import prepare_comparison_package


def prepare(workspace, retained, original, output):
    here = Path(__file__).resolve().parent
    inputs = output.parent / 'native-inputs'
    inputs.mkdir(exist_ok=True)
    entry = json.loads((here / 'native-entries.json').read_text())[0]
    header = native_entry_header(original=original / 'libjq-1.dll',
        expected_sha256='50d05ffd1f3cdbb5257f2cda429d9b920d95c091bb88a9d8bcdcb08ae9bacb1d',
        module='libjq-1.dll', entry_rva=entry['entry_rva'], end_rva=entry['end_rva'],
        additional_ranges=entry['additional_ranges'], installer='install_tests')
    (inputs / 'native-entry.h').write_text(header)
    environment = native_environment(retained)
    environment['runtime_files']['jq.exe'] = original / 'jq.exe'
    for name, data in files().items():
        (inputs / name).write_bytes(data)
        environment['runtime_files'][name] = inputs / name
    prepare_comparison_package(**runpy.run_path(str(workspace / 'prepare.py'))['source_inputs'](),
        **environment, adapter_files={'native-runtime.c': here / 'native-runtime.c'},
        include_files={**{p.name: p for p in (workspace / 'headers').iterdir()},
            'native-entry.h': inputs / 'native-entry.h', **native_adapter_headers()},
        original_files=['runtime/jq.exe', 'runtime/libjq-1.dll'], oracle_kind='native-original', cases=cases(),
        observation_fields=['exit_code', 'stdout', 'stderr', 'state'],
        program_driver=dict(kind='pe32-import', image='runtime/jq.exe', library='jq-tests.dll',
            symbol='spx_jq_tests_anchor', process=dict(exit_codes=[0, 1, 2, 3, 4, 5], drive='P')),
        assumptions=json.loads((workspace / 'assumptions.json').read_text()),
        scope='Normal --run-tests, original entry/helpers disabled, exact output/exit and three-worker create/join observations.',
        output=output)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('workspace', 'retained', 'original', 'output'):
        parser.add_argument(name, type=Path)
    args = parser.parse_args()
    prepare(args.workspace.resolve(), args.retained.resolve(), args.original.resolve(), args.output.resolve())
