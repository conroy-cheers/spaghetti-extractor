"""Author shared value-runtime operations through the public workflow."""
import argparse
import json
from pathlib import Path
import subprocess

from spaghetti_extractor.components.service_authoring import component_interface, OperationDefinition


def prepare(project, output, toolkit):
    here = Path(__file__).resolve().parent
    output.mkdir(parents=True)
    rows = json.loads((here / 'native-entries.json').read_text())
    interface = component_interface(component_id='value-runtime', services={}, types=[
        dict(id='unit', kind='void'),
        dict(id='value_input', kind='opaque', nominal_id='jq.value-runtime-entry-arguments'),
        dict(id='value_output', kind='opaque', nominal_id='jq.value-runtime-entry-result'),
    ], operations={row['operation']: OperationDefinition(
        [('input', 'value_input'), ('output', 'value_output')], 'unit') for row in rows})
    (output / 'interface.json').write_text(json.dumps(interface.to_payload()) + '\n')
    command = [str(toolkit), 'component', 'start', 'jq', 'value-runtime',
               '--interface-intent', str(output / 'interface.json'),
               '--assumption-file', str(here / 'BOUNDARY.md'), '--output', str(output / 'authoring')]
    for name in ('component.c', 'value-runtime.c', 'slice.c', 'value-runtime-inputs.h', 'value-runtime-renames.h'):
        command += ['--source-file', 'source/' + name + '=' + str(here / name)]
    for name in ('jv.h', 'jq.h', 'jv_alloc.h', 'jv_unicode.h'):
        command += ['--include-file', name + '=' + str(project / 'backends/jq/src' / name)]
    subprocess.run(command, check=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('project', 'output', 'toolkit'):
        parser.add_argument(name, type=Path)
    args = parser.parse_args()
    prepare(args.project.resolve(), args.output.resolve(), args.toolkit.resolve())
