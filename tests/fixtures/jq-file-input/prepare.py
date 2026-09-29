"""Author jq file loading with a reusable Windows-profile input library.

Run inside the lifting shell. Inputs are the retained pinned source project and
an installed toolkit. This recipe uses public component authoring facilities.
"""
from pathlib import Path
import argparse
import json
import subprocess

from spaghetti_extractor.components.service_authoring import component_interface, OperationDefinition


def prepare(project, output, toolkit):
    output.mkdir(parents=True)
    inputs = output / 'inputs'
    inputs.mkdir()
    source = project / 'backends/jq/src'
    runtime = Path(__file__).resolve().parents[1] / 'portable-runtime'
    interface = component_interface(component_id='file-input', services={}, types=[
        dict(id='unit', kind='void'),
        dict(id='input', kind='opaque', nominal_id='jq.borrowed-file-name-and-mode'),
        dict(id='output', kind='opaque', nominal_id='jq.owned-file-value'),
    ], operations={'load': OperationDefinition([('input', 'input'), ('output', 'output')], 'unit')})
    (inputs / 'interface.json').write_text(json.dumps(interface.to_payload()) + '\n')
    (inputs / 'file-input.h').write_text('''#ifndef SPX_JQ_FILE_INPUT_H
#define SPX_JQ_FILE_INPUT_H
#include "jv.h"
struct spx_opaque_input_v5 { const char *filename; int raw; };
struct spx_opaque_output_v5 { jv value; };
jv portable_load_file(const char *, int);
#endif
''')
    (inputs / 'component.c').write_text('''#include "portable-component-implementation.h"
#include "file-input.h"
void lifted_file_input_load(spx_file_input_context_v5 *context,
    struct spx_opaque_input_v5 *input, struct spx_opaque_output_v5 *output) {
    (void)context; (void)&jv_is_valid;
    output->value = portable_load_file(input->filename, input->raw);
}
''')
    # Keep the reviewed C independently of whether this project has already
    # removed the old backend body during a previous component export.
    (inputs / 'load.c').write_bytes((Path(__file__).with_name('load.c')).read_bytes())
    (inputs / 'BOUNDARY.md').write_text('''# jq file input

Borrows a NUL-terminated filename for the call; raw is a boolean. Returns an
owned jv string, array of parsed values, or invalid value with an error message.
The reader owns and closes its stream, and releases parser state on every exit.
Existing value, parser, allocator and UTF-8 services retain their reviewed ABI.
Input chunks remain 4096 decoded bytes with completion of a split UTF-8 sequence.

The supplied Windows-profile file library is also available to other consumers.
Each stream owns its decoding and EOF state; independent opens do not share it.
Text input translates CRLF and treats Ctrl-Z as EOF; binary input preserves bytes.
Host pathname lookup folds ASCII case component by component. Non-ASCII spelling
matches exactly. The shared path provider supplies lexical canonicalization and
configured drive/UNC mappings; program-support owns its single implementation.
Unmapped namespaces fail explicitly. Ambiguous folded names, arbitrary devices,
changing directory contents, DBCS/code-page conversion and Windows sharing or
permission rules are outside this provider's scope. Ordinary host allocation and
stdio are explicit services. All consumers must use the same namespace mapping.
Native comparisons and real portable program workloads qualify only tested cases.
No declared service or opaque pointer is a checked formal summary.
''')
    command = [str(toolkit), 'component', 'start', 'jq', 'file-input',
               '--interface-intent', str(inputs / 'interface.json'),
               '--assumption-file', str(inputs / 'BOUNDARY.md'), '--output', str(output / 'authoring')]
    for name in ('component.c', 'load.c', 'file-input.h'):
        command += ['--source-file', 'source/' + name + '=' + str(inputs / name)]
    for name in ('windows-files.c', 'windows-files.h'):
        command += ['--source-file', 'source/' + name + '=' + str(runtime / name)]
    for name in ('jv.h', 'jv_unicode.h'):
        command += ['--include-file', name + '=' + str(source / name)]
    command += ['--include-file', 'windows-paths.h=' + str(runtime / 'windows-paths.h')]
    subprocess.run(command, check=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('project', 'output', 'toolkit'):
        parser.add_argument(name, type=Path)
    args = parser.parse_args()
    prepare(args.project.resolve(), args.output.resolve(), args.toolkit.resolve())
