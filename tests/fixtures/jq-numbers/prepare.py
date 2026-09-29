"""Author numeric storage and value operations through the public workflow."""
import argparse
import json
from pathlib import Path
import subprocess

from spaghetti_extractor.components.service_authoring import component_interface, OperationDefinition


def prepare(project, output, toolkit):
    here = Path(__file__).resolve().parent
    output.mkdir(parents=True)
    rows = json.loads((here / 'native-entries.json').read_text())
    interface = component_interface(component_id='number-values', services={}, types=[
        dict(id='unit', kind='void'),
        dict(id='number_input', kind='opaque', nominal_id='jq.number-entry-arguments'),
        dict(id='number_output', kind='opaque', nominal_id='jq.number-entry-result'),
    ], operations={row['operation']: OperationDefinition(
        [('input', 'number_input'), ('output', 'number_output')], 'unit') for row in rows})
    (output / 'interface.json').write_text(json.dumps(interface.to_payload()) + '\n')
    command = [str(toolkit), 'component', 'start', 'jq', 'number-values',
               '--interface-intent', str(output / 'interface.json'),
               '--assumption-file', str(here / 'BOUNDARY.md'), '--output', str(output / 'authoring')]
    for name in ('component.c', 'numbers.c', 'number-inputs.h', 'number-renames.h'):
        command += ['--source-file', 'source/' + name + '=' + str(here / name)]
    for name in ('jv.h', 'jq.h', 'jv_alloc.h', 'jv_dtoa.h', 'jv_dtoa_tsd.h'):
        command += ['--include-file', name + '=' + str(project / 'backends/jq/src' / name)]
    for name in ('decNumber.h', 'decContext.h'):
        command += ['--include-file', name + '=' + str(project / 'backends/jq/vendor/decNumber' / name)]
    subprocess.run(command, check=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('project', 'output', 'toolkit'):
        parser.add_argument(name, type=Path)
    args = parser.parse_args()
    prepare(args.project.resolve(), args.output.resolve(), args.toolkit.resolve())
