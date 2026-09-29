"""Bind real process entry to authored CLI C; reuse retained native dependencies."""
import argparse
import json
from pathlib import Path
import runpy

from cases import cases, files
from spaghetti_extractor.components.comparison_environment import native_environment, native_adapter_headers
from spaghetti_extractor.components.comparison_original import native_entry_header
from spaghetti_extractor.components.comparison_package import prepare_comparison_package

EXE_SHA = '1d4ccabec8ad11a04f7f45b105809847ca91d018d210746e5a7b4d35b3c84ac6'


def prepare(workspace, retained, original, output):
    here = Path(__file__).resolve().parent
    bindings = output.parent / 'native-inputs'
    bindings.mkdir(exist_ok=True)
    header = native_entry_header(original=original / 'jq.exe', expected_sha256=EXE_SHA,
        module=None, entry_rva=0x245e, end_rva=0x490c,
        additional_ranges=((0x1440, 0x245e),), installer='install_cli')
    (bindings / 'native-entry.h').write_text(header)
    environment = native_environment(retained)
    environment['runtime_files']['jq.exe'] = original / 'jq.exe'
    for name, data in files().items():
        (bindings / name).write_bytes(data)
        environment['runtime_files'][name] = bindings / name
    runtime = here.parent / 'portable-runtime'
    prepare_comparison_package(**runpy.run_path(str(workspace / 'prepare.py'))['source_inputs'](),
        **environment,
        adapter_files={'native-runtime.c': here / 'native-runtime.c', 'windows-output.c': runtime / 'windows-output.c'},
        include_files={**{p.name: p for p in (workspace / 'headers').iterdir()},
            'original-configuration.h': here / 'original-configuration.h',
            'windows-output.h': runtime / 'windows-output.h',
            'native-entry.h': bindings / 'native-entry.h', **native_adapter_headers()},
        original_files=['runtime/jq.exe', 'runtime/libjq-1.dll'], oracle_kind='native-original', cases=cases(),
        observation_fields=['exit_code', 'stdout', 'stderr', 'state'],
        program_driver=dict(kind='pe32-import', image='runtime/jq.exe', library='jq-cli.dll',
            symbol='spx_jq_cli_anchor', process=dict(exit_codes=[0, 1, 2, 3, 4, 5], drive='P')),
        assumptions=json.loads((workspace / 'assumptions.json').read_text()),
        scope='Normal jq startup with original control, disabled CLI body and helpers, exact redirected output and exit status.',
        output=output)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('workspace', 'retained', 'original', 'output'):
        parser.add_argument(name, type=Path)
    args = parser.parse_args()
    prepare(args.workspace.resolve(), args.retained.resolve(), args.original.resolve(), args.output.resolve())
