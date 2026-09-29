"""Author jq's builtin module using the existing component workflow."""
from pathlib import Path
import argparse
import json
import subprocess

from spaghetti_extractor.components.service_authoring import component_interface, OperationDefinition


def prepare(project, output, toolkit):
    here = Path(__file__).resolve().parent
    output.mkdir(parents=True)
    rows = json.loads((here/'native-entries.json').read_text())
    interface = component_interface(component_id='builtin-library', services={}, types=[
        dict(id='unit', kind='void'),
        dict(id='builtin_input', kind='opaque', nominal_id='jq.builtin-entry-arguments'),
        dict(id='builtin_output', kind='opaque', nominal_id='jq.builtin-entry-result'),
    ], operations={row['name']: OperationDefinition([('input','builtin_input'),('output','builtin_output')], 'unit')
                   for row in rows})
    (output/'interface.json').write_text(json.dumps(interface.to_payload())+'\n')
    command = [str(toolkit),'component','start','jq','builtin-library',
        '--interface-intent',str(output/'interface.json'),'--assumption-file',str(here/'BOUNDARY.md'),
        '--output',str(output/'authoring')]
    for name in ('component.c','builtins.c','builtin-api.h','builtin-inputs.h','builtin-renames.h',
                 'builtin-profile.h','builtins-jq.h'):
        command += ['--source-file','source/'+name+'='+str(here/name)]
    for name in ('jq.h','jv.h','jv_alloc.h','compile.h','locfile.h','bytecode.h','opcode_list.h',
                 'builtin.h','linker.h','jq_parser.h','jv_unicode.h','jv_dtoa.h','jv_dtoa_tsd.h',
                 'jv_private.h','util.h','libm.h'):
        command += ['--include-file',name+'='+str(project/'backends/jq/src'/name)]
    command += ['--include-file','oniguruma.h='+str(project/'backends/jq/vendor/oniguruma/src/oniguruma.h')]
    subprocess.run(command,check=True)


if __name__ == '__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('project','output','toolkit'):parser.add_argument(name,type=Path)
    args=parser.parse_args()
    prepare(args.project.resolve(),args.output.resolve(),args.toolkit.resolve())
