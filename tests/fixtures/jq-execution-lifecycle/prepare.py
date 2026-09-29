"""Prepare the jq lifecycle boundary using the public authoring API."""
from pathlib import Path
import argparse
import hashlib
import json
import subprocess

from spaghetti_extractor.components.service_authoring import component_interface, OperationDefinition


def prepare(project, output, toolkit):
    here = Path(__file__).resolve().parent
    output.mkdir(parents=True)
    vm = project / 'lifted/components/vm-next/sources/source/component.c'
    source = vm.read_text()
    layout = source[source.index('struct jq_state {'):source.index('static int frame_size')]
    if layout not in (here / 'state-layout.h').read_text():
        raise ValueError('review the changed shared interpreter state layout')
    rows = json.loads((here / 'native-entries.json').read_text())
    interface = component_interface(component_id='execution-lifecycle', services={}, types=[
        dict(id='unit', kind='void'),
        dict(id='lifecycle_input', kind='opaque', nominal_id='jq.lifecycle-arguments'),
        dict(id='lifecycle_output', kind='opaque', nominal_id='jq.lifecycle-result'),
    ], operations={row.get('operation', row['name']): OperationDefinition(
        [('input', 'lifecycle_input'), ('output', 'lifecycle_output')], 'unit') for row in rows})
    (output / 'interface.json').write_text(json.dumps(interface.to_payload()) + '\n')
    (output / 'shared-layout.json').write_text(json.dumps(dict(
        provider='vm-next', path=str(vm), sha256=hashlib.sha256(layout.encode()).hexdigest())) + '\n')
    command = [str(toolkit), 'component', 'start', 'jq', 'execution-lifecycle',
               '--interface-intent', str(output / 'interface.json'),
               '--assumption-file', str(here / 'BOUNDARY.md'), '--output', str(output / 'authoring')]
    for name in ('component.c', 'lifecycle.c', 'lifecycle-api.h', 'lifecycle-renames.h',
                 'lifecycle-inputs.h', 'state-layout.h', 'execution-stack.h'):
        command += ['--source-file', 'source/' + name + '=' + str(here / name)]
    for name in ('jq.h', 'jv.h', 'jv_alloc.h', 'compile.h', 'locfile.h', 'bytecode.h',
                 'opcode_list.h', 'builtin.h', 'linker.h'):
        command += ['--include-file', name + '=' + str(project / 'backends/jq/src' / name)]
    subprocess.run(command, check=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('project', 'output', 'toolkit'):
        parser.add_argument(name, type=Path)
    args = parser.parse_args()
    prepare(args.project.resolve(), args.output.resolve(), args.toolkit.resolve())
