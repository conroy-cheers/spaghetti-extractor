"""Author the shared runtime state using public component facilities."""
import argparse
import json
from pathlib import Path
import subprocess

from spaghetti_extractor.components.service_authoring import component_interface, OperationDefinition


def prepare(project, output, toolkit):
    here = Path(__file__).resolve().parent
    output.mkdir(parents=True)
    rows = json.loads((here / 'native-entries.json').read_text())
    interface = component_interface(component_id='runtime-contexts', services={}, types=[
        dict(id='unit', kind='void'),
        dict(id='context_result', kind='opaque', nominal_id='jq.live-runtime-context-result'),
    ], operations={row['operation']: OperationDefinition([('output', 'context_result')], 'unit') for row in rows})
    (output / 'interface.json').write_text(json.dumps(interface.to_payload()) + '\n')
    command = [str(toolkit), 'component', 'start', 'jq', 'runtime-contexts',
        '--interface-intent', str(output / 'interface.json'),
        '--state-owners', str(here / 'state-owners.json'),
        '--assumption-file', str(here / 'BOUNDARY.md'), '--output', str(output / 'authoring')]
    for name in ('component.c', 'contexts.c', 'context-inputs.h', 'context-services.h'):
        command += ['--source-file', 'source/' + name + '=' + str(here / name)]
    for name in ('jv.h', 'jq.h', 'jv_alloc.h', 'jv_dtoa.h'):
        command += ['--include-file', name + '=' + str(project / 'backends/jq/src' / name)]
    for name in ('decNumber.h', 'decContext.h'):
        command += ['--include-file', name + '=' + str(project / 'backends/jq/vendor/decNumber' / name)]
    headers = project / 'lifted/components/allocator-runtime/sources/headers'
    for path in headers.glob('winpthread-*.h'):
        command += ['--include-file', path.name + '=' + str(path)]
    if not (headers / 'winpthread-pthread.h').is_file():
        raise ValueError('requires the existing allocator runtime pthread ABI headers')
    subprocess.run(command, check=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('project', 'output', 'toolkit'):
        parser.add_argument(name, type=Path)
    args = parser.parse_args()
    prepare(args.project.resolve(), args.output.resolve(), args.toolkit.resolve())
