"""Prepare a program-support workspace through public component authoring."""
import argparse
import json
from pathlib import Path
import subprocess

from spaghetti_extractor.components.service_authoring import component_interface, OperationDefinition


def prepare(project, output, toolkit):
    here = Path(__file__).resolve().parent
    output.mkdir(parents=True)
    rows = json.loads((here / 'native-entries.json').read_text())
    interface = component_interface(component_id='program-support', services={}, types=[
        dict(id='unit', kind='void'),
        dict(id='support_input', kind='opaque', nominal_id='jq.program-support-live-input'),
        dict(id='support_output', kind='opaque', nominal_id='jq.program-support-result'),
    ], operations={row['operation']: OperationDefinition(
        [('input', 'support_input'), ('output', 'support_output')], 'unit') for row in rows})
    (output / 'interface.json').write_text(json.dumps(interface.to_payload()) + '\n')
    command = [str(toolkit), 'component', 'start', 'jq', 'program-support',
               '--interface-intent', str(output / 'interface.json'),
               '--state-owners', str(here / 'state-owners.json'),
               '--assumption-file', str(here / 'BOUNDARY.md'), '--output', str(output / 'authoring')]
    for name in ('component.c', 'unicode.c', 'bytecode.c', 'locations.c', 'utilities.c', 'support-inputs.h', 'support-renames.h'):
        command += ['--source-file', 'source/' + name + '=' + str(here / name)]
    for name in ('windows-paths.c', 'windows-path-environment.c', 'windows-path-parts.c', 'windows-paths.h'):
        command += ['--source-file', 'source/' + name + '=' + str(here.parent / 'portable-runtime' / name)]
    for name in ('jv.h', 'jq.h', 'jv_alloc.h', 'jv_unicode.h', 'jv_utf8_tables.h', 'bytecode.h', 'opcode_list.h', 'locfile.h'):
        command += ['--include-file', name + '=' + str(project / 'backends/jq/src' / name)]
    subprocess.run(command, check=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('project', 'output', 'toolkit'):
        parser.add_argument(name, type=Path)
    args = parser.parse_args()
    prepare(args.project.resolve(), args.output.resolve(), args.toolkit.resolve())
