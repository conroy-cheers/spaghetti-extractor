"""Author the complete test-runner entry using existing component facilities."""
import argparse
import json
from pathlib import Path
import subprocess

from spaghetti_extractor.components.service_authoring import component_interface, OperationDefinition


def prepare(project, output, toolkit):
    here = Path(__file__).resolve().parent
    output.mkdir(parents=True)
    interface = component_interface(component_id='test-runner', services={}, types=[
        dict(id='status', kind='integer', width_bits=32, signed=True),
        dict(id='test_input', kind='opaque', nominal_id='jq.test-runner-live-arguments'),
    ], operations={'run': OperationDefinition([('input', 'test_input')], 'status')})
    (output / 'interface.json').write_text(json.dumps(interface.to_payload()) + '\n')
    command = [str(toolkit), 'component', 'start', 'jq', 'test-runner',
        '--interface-intent', str(output / 'interface.json'),
        '--assumption-file', str(here / 'BOUNDARY.md'), '--output', str(output / 'authoring')]
    for name in ('component.c', 'runner.c', 'values.c', 'test-input.h'):
        command += ['--source-file', 'source/' + name + '=' + str(here / name)]
    for name in ('jv.h', 'jq.h'):
        command += ['--include-file', name + '=' + str(project / 'backends/jq/src' / name)]
    command += ['--include-file', 'windows-files.h=' + str(here.parent / 'portable-runtime/windows-files.h')]
    headers = project / 'lifted/components/allocator-runtime/sources/headers'
    for path in headers.glob('winpthread-*.h'):
        command += ['--include-file', path.name + '=' + str(path)]
    subprocess.run(command, check=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('project', 'output', 'toolkit'):
        parser.add_argument(name, type=Path)
    args = parser.parse_args()
    prepare(args.project.resolve(), args.output.resolve(), args.toolkit.resolve())
