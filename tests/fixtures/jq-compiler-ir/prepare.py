"""Prepare jq's instruction-graph module through the public authoring API."""
from pathlib import Path
import argparse
import hashlib
import json
import subprocess

from spaghetti_extractor.components.service_authoring import component_interface, OperationDefinition


def prepare(project, output, toolkit):
    here = Path(__file__).resolve().parent
    output.mkdir(parents=True)
    layout = project / 'lifted/components/bytecode-compiler/sources/source/instruction-layout.h'
    if layout.read_bytes() != (here / 'instruction-layout.h').read_bytes():
        raise ValueError('review the changed shared instruction layout before authoring this module')
    rows = json.loads((here / 'native-entries.json').read_text())
    interface = component_interface(component_id='compiler-ir', services={}, types=[
        dict(id='unit', kind='void'),
        dict(id='ir_input', kind='opaque', nominal_id='jq.ir-operation-arguments'),
        dict(id='ir_output', kind='opaque', nominal_id='jq.ir-operation-result'),
    ], operations={row['name']: OperationDefinition([('input', 'ir_input'), ('output', 'ir_output')], 'unit')
                   for row in rows})
    (output / 'interface.json').write_text(json.dumps(interface.to_payload()) + '\n')
    (output / 'shared-layout.json').write_text(json.dumps(dict(
        provider='bytecode-compiler', path=str(layout),
        sha256=hashlib.sha256(layout.read_bytes()).hexdigest())) + '\n')
    command = [str(toolkit), 'component', 'start', 'jq', 'compiler-ir',
               '--interface-intent', str(output / 'interface.json'),
               '--assumption-file', str(here / 'BOUNDARY.md'), '--output', str(output / 'authoring')]
    for name in ('component.c', 'ir.c', 'ir-api.h', 'ir-renames.h', 'ir-inputs.h', 'instruction-layout.h'):
        command += ['--source-file', 'source/' + name + '=' + str(here / name)]
    for name in ('jq.h', 'jv.h', 'jv_alloc.h', 'compile.h', 'locfile.h', 'bytecode.h', 'opcode_list.h'):
        command += ['--include-file', name + '=' + str(project / 'backends/jq/src' / name)]
    subprocess.run(command, check=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('project', 'output', 'toolkit'):
        parser.add_argument(name, type=Path)
    args = parser.parse_args()
    prepare(args.project.resolve(), args.output.resolve(), args.toolkit.resolve())
