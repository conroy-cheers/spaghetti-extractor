"""Author the jq CLI through the public component workspace command."""
import argparse
import json
from pathlib import Path
import subprocess

from spaghetti_extractor.components.service_authoring import component_interface, OperationDefinition


def prepare(project, output, toolkit):
    here = Path(__file__).resolve().parent
    output.mkdir(parents=True)
    interface = component_interface(component_id='cli', services={}, types=[
        dict(id='unit', kind='void'),
        dict(id='arguments', kind='opaque', nominal_id='jq.live-utf8-process-arguments'),
    ], operations={'run': OperationDefinition([('input', 'arguments')], 'unit')})
    (output / 'interface.json').write_text(json.dumps(interface.to_payload()) + '\n')
    command = [str(toolkit), 'component', 'start', 'jq', 'cli',
               '--interface-intent', str(output / 'interface.json'),
               '--assumption-file', str(here / 'BOUNDARY.md'), '--output', str(output / 'authoring')]
    for name in ('component.c', 'cli.c', 'cli-input.h', 'cli-runtime.h'):
        command += ['--source-file', 'source/' + name + '=' + str(here / name)]
    for name in ('jv.h', 'jq.h'):
        command += ['--include-file', name + '=' + str(project / 'backends/jq/src' / name)]
    subprocess.run(command, check=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('project', 'output', 'toolkit'):
        parser.add_argument(name, type=Path)
    args = parser.parse_args()
    prepare(args.project.resolve(), args.output.resolve(), args.toolkit.resolve())
