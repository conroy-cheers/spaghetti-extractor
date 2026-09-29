"""Author the jq equality, containment and merging with the public component workflow."""
from pathlib import Path
import argparse
import json
import subprocess

from spaghetti_extractor.components.service_authoring import component_interface, OperationDefinition


def prepare(project, output, toolkit):
    here = Path(__file__).resolve().parent
    output.mkdir(parents=True)
    rows = json.loads((here / 'native-entries.json').read_text())
    interface = component_interface(component_id='value-relations', services={}, types=[
        dict(id='unit', kind='void'),
        dict(id='input', kind='opaque', nominal_id='jq.owned-value-algorithm-arguments'),
        dict(id='output', kind='opaque', nominal_id='jq.value-or-comparison-result'),
    ], operations={row[0]: OperationDefinition([('input', 'input'), ('output', 'output')], 'unit')
                   for row in rows})
    (output / 'interface.json').write_text(json.dumps(interface.to_payload()) + '\n')
    command = [str(toolkit), 'component', 'start', 'jq', 'value-relations',
               '--interface-intent', str(output / 'interface.json'),
               '--assumption-file', str(here / 'BOUNDARY.md'), '--output', str(output / 'authoring')]
    for name in ('component.c', 'relations.c', 'value-relations.h'):
        command += ['--source-file', 'source/' + name + '=' + str(here / name)]
    for name in ('jv.h', 'jv_alloc.h', 'jv_private.h'):
        command += ['--include-file', name + '=' + str(project / 'backends/jq/src' / name)]
    subprocess.run(command, check=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('project', 'output', 'toolkit'):
        parser.add_argument(name, type=Path)
    args = parser.parse_args()
    prepare(args.project.resolve(), args.output.resolve(), args.toolkit.resolve())
