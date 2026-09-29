"""Prepare a native comparison of file loading; no pilot rebuild is needed."""
from pathlib import Path
import argparse
import json
import runpy

from spaghetti_extractor.components.comparison_environment import native_environment, native_adapter_headers
from spaghetti_extractor.components.comparison_original import native_entry_header
from spaghetti_extractor.components.comparison_package import prepare_comparison_package


def prepare(workspace, retained, output):
    here = Path(__file__).resolve().parent
    bindings = output.parent / 'native-inputs'
    bindings.mkdir(exist_ok=True)
    (bindings / 'native-entry.h').write_text(native_entry_header(
        original=retained / 'runtime/libjq-1.dll',
        expected_sha256='50d05ffd1f3cdbb5257f2cda429d9b920d95c091bb88a9d8bcdcb08ae9bacb1d',
        module='libjq-1.dll', entry_rva=0x39ef3, end_rva=0x3a460))
    (bindings / 'native-runtime.c').write_text('''#include <windows.h>
#include "jv_unicode.h"
const char *jvp_utf8_backtrack(const char *start, const char *min, int *missing) {
    HMODULE module = GetModuleHandleA("libjq-1.dll");
    if (!module) ExitProcess(84);
    return ((const char *(*)(const char *, const char *, int *))
        ((unsigned char *)module + 0x3fc60))(start, min, missing);
}
''')
    samples = [('empty', b''), ('lines', b'one\r\ntwo\nthree\rfour\r'),
               ('ctrl-z', b'before\x1aafter\n'), ('cr-before-ctrl-z', b'one\r\x1aafter'),
               ('nul', b'a\0b\r\n'), ('utf8', 'a\r\n\u00e9\U0001f642\n'.encode()),
               ('cr-boundary', b'a'*4095+b'\r\nb'),
               ('utf8-boundary', b'a'*4095+'\U0001f642'.encode()+b'\r\nz'),
               ('truncated-utf8', b'a\xf0\x9f'), ('bad-utf8', b'a\xff\r\nb')]
    cases = [dict(id=name, arguments=[data.hex(), '1', 'fixture.bin']) for name, data in samples]
    for name, data in [('json-values', b'1\r\n{"x":2}\r\n[3]\n'),
                       ('json-eof-number', b'123'), ('json-ctrl-z', b'1\r\n\x1aINVALID'),
                       ('json-invalid', b'[1, broken]\n'), ('json-empty', b''),
                       ('json-utf8-boundary', b'"'+b'a'*4094+'\U0001f642'.encode()+b'"\r\n')]:
        cases.append(dict(id=name, arguments=[data.hex(), '0', 'fixture.bin']))
    cases += [dict(id='case-folded', arguments=['746578740d0a', '1', 'FIXTURE.BIN']),
              dict(id='missing', arguments=['', '1', 'absent.bin']),
              dict(id='directory', arguments=['', '1', 'directory'])]
    for index, name in enumerate(['.\\fixture.bin', 'absent\\..\\fixture.bin',
                                  'fixture.bin. ', 'Z:fixture.bin', 'z:FIXTURE.BIN', 'NUL']):
        cases.append(dict(id='namespace-' + str(index), arguments=['746578740d0a', '1', name]))
    # Retain the large bytes above, but generate them inside the driver instead
    # of sending an 8 KB argument through the native process launcher.
    expanded = {row['id']: row['arguments'][0] for row in cases}
    for row in cases:
        if row['id'] in ('cr-boundary', 'utf8-boundary', 'json-utf8-boundary'):
            row['arguments'][0] = {'cr-boundary': '@raw-cr', 'utf8-boundary': '@raw-utf8',
                                    'json-utf8-boundary': '@json-utf8'}[row['id']]
    (output.parent / 'fixture-bytes.json').write_text(json.dumps(expanded, indent=2) + '\n')
    (output.parent / 'cases.json').write_text(json.dumps(cases, indent=2) + '\n')
    prepare_comparison_package(
        **runpy.run_path(str(workspace / 'prepare.py'))['source_inputs'](),
        **native_environment(retained),
        adapter_files={'driver.c': here / 'driver.c', 'native-runtime.c': bindings / 'native-runtime.c',
                       'windows-path-environment.c': here.parent / 'portable-runtime/windows-path-environment.c',
                       'allocation-observer.c': here.parent / 'jq-array-storage/allocation-observer.c'},
        include_files={**{p.name: p for p in (workspace / 'headers').iterdir()},
                       'native-entry.h': bindings / 'native-entry.h',
                       'allocation-observer.h': here.parent / 'jq-array-storage/allocation-observer.h',
                       **native_adapter_headers()},
        original_files=['runtime/libjq-1.dll'], oracle_kind='native-original', cases=cases,
        observation_fields=['values', 'allocation_lifetime'],
        assumptions=json.loads((workspace / 'assumptions.json').read_text()) + [
            'Driver writes identical binary files separately for each process, then calls the real entry three times. The original body is trapped on the source side. File-library host allocations are separate from the observed jq value heap.'],
        scope='Native jq file loading: text translation, raw/JSON input, split UTF-8, failures and repeated ownership cleanup.',
        output=output)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('workspace', 'retained', 'output'):
        parser.add_argument(name, type=Path)
    args = parser.parse_args()
    prepare(args.workspace.resolve(), args.retained.resolve(), args.output.resolve())
