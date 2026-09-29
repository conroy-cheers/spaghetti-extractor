"""Prepare the jq input-state component using ordinary public C authoring."""
from pathlib import Path
import argparse
import json
import subprocess

from spaghetti_extractor.components.service_authoring import component_interface, OperationDefinition


def prepare(project, output, toolkit):
    here = Path(__file__).resolve().parent
    output.mkdir(parents=True)
    operations = ('create', 'parser', 'add', 'next', 'destroy', 'errors', 'position', 'filename', 'line')
    interface = component_interface(component_id='input-stream', services={}, types=[
        dict(id='unit', kind='void'),
        dict(id='input', kind='opaque', nominal_id='jq.input-state-operation-arguments'),
        dict(id='output', kind='opaque', nominal_id='jq.input-state-operation-result'),
    ], operations={name: OperationDefinition([('input', 'input'), ('output', 'output')], 'unit')
                   for name in operations})
    (output / 'interface.json').write_text(json.dumps(interface.to_payload()) + '\n')
    command = [str(toolkit), 'component', 'start', 'jq', 'input-stream',
               '--interface-intent', str(output / 'interface.json'),
               '--assumption-file', str(here / 'BOUNDARY.md'), '--output', str(output / 'authoring')]
    for name in ('component.c', 'input.c', 'input-stream.h'):
        command += ['--source-file', 'source/' + name + '=' + str(here / name)]
    for name in ('jq.h', 'jv.h', 'jv_alloc.h'):
        command += ['--include-file', name + '=' + str(project / 'backends/jq/src' / name)]
    command += ['--include-file', 'windows-files.h=' + str(here.parent / 'portable-runtime/windows-files.h')]
    subprocess.run(command, check=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('project', 'output', 'toolkit'):
        parser.add_argument(name, type=Path)
    args = parser.parse_args()
    prepare(args.project.resolve(), args.output.resolve(), args.toolkit.resolve())
