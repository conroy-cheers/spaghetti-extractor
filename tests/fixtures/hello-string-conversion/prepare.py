"""Prepare a new manually defined Hello string boundary through documented APIs."""
import argparse
from pathlib import Path
import time

from spaghetti_extractor.components.comparison_package import prepare_comparison_package
from spaghetti_extractor.components.comparison_original import native_entry_header
from spaghetti_extractor.util import sha256_file, write_json
from spaghetti_extractor.components.comparison_environment import native_environment, native_adapter_headers
from spaghetti_extractor.components.comparison_pe32_program import prepare_routine_image
from declarations import interface

HERE = Path(__file__).resolve().parent
PE = '71b228f2babc9d3b4095ecf355db676c8ed8b45a7c8a7d350f47e962b4bf554c'
ASSUMPTIONS = [
    'Complete rpl_mbsrtowcs at RVA 0x29a4..0x2b28 and cold 0x14628..0x14630; implicit state at 0x30300. Real instruction analysis supplied the boundary and C; no prepared component or GNU algorithm source was copied.',
    'The live input cursor references a NUL-terminated readable byte span. Limit bounds a live uint16_t array; widths are target widths, not host wchar_t. Array byte extents and cursor differences fit signed 32 bits; output limit is below 2^30. No invalid pointers, wraparound or volatile memory is admitted.',
    'Reuse multibyte-objects.h four-byte state and call-scoped pointer proxies. Explicit state, implicit state and explicit aliases of implicit state are included. Output may share the input uint16_t backing array; state/output and cursor/output overlaps are excluded.',
    'Count-only conversion copies four state bytes and does not update cursor or original state. Writing conversion updates live output, state and cursor in the original order. A missing output ignores the supplied limit.',
    'decode16 is a synchronous retained native service locally; normal program assembly can reach the previously lifted conversion through its existing entry. C and Japanese_Japan.932 use actual CRT behavior. The third context is an explicit controlled service, including errors and an incomplete-result abort.',
    'Native EILSEQ is observable number 42; invalid_state forwards actual CRT abort. Original startup/TLS are omitted for local routine comparisons and separately exercised in normal-entry program runs. No reentrancy, concurrent state access or callbacks are claimed.',
    'Observations cover returns, errno, cursor offsets, input/output contents and frames, explicit/implicit state and ordered decoder arguments/results/state effects. Finite tests and declarations do not constitute checked summaries or strong qualification.',
]


def prepare(original, output):
    started = time.monotonic()
    if sha256_file(original) != PE: raise ValueError('requires pinned Hello bytes')
    environment = native_environment()
    output.mkdir(parents=True, exist_ok=False)
    library=output/'image/hello-routines.dll'
    write_json(output/'image/image-preparation.json',prepare_routine_image(original,library))
    entry=output/'string-entry.h'
    entry.write_text(native_entry_header(original=original,expected_sha256=PE,module=None,
        entry_rva=0x29a4,end_rva=0x2b28,additional_ranges=((0x14628,0x14630),),
        installer='spx_install_string_entry'))
    runtime = {**environment['runtime_files'], 'hello.exe': original, 'hello-routines.dll': library}
    cases = [dict(id=f'context-{mode}-transport-{transport}', arguments=[str(mode), str(transport)])
             for mode in range(3) for transport in range(3)]
    cases += [dict(id=f'terminal-{transport}', arguments=['terminal', str(transport)]) for transport in range(3)]
    prepare_comparison_package(interface_package=interface(), target_id='gnu-hello', component_id='string-conversion',
        source_files={name: HERE/name for name in ('string.c', 'string-objects.h')},
        operation_symbols={'convert': 'string_convert'},
        adapter_files={name: HERE/name for name in ('bridge.c', 'driver.c')},
        include_files={**{name: HERE/name for name in ('string-objects.h', 'string-runtime.h', 'BOUNDARY.md')},
            **{name: HERE.parent/'hello-multibyte'/name for name in ('multibyte-objects.h', 'COPYING.hello')},
            **native_adapter_headers('pe32-entry-hook.h', 'pe32-import-hook.h', 'pe32-process-observer.h'),
            'string-entry.h': entry,
            'image-preparation.json': output/'image/image-preparation.json'},
        original_files=['runtime/hello.exe', 'runtime/hello-routines.dll', 'headers/image-preparation.json'],
        oracle_kind='native-original', cases=cases, observation_fields=['sequences', 'terminal'],
        assumptions=ASSUMPTIONS, scope='Complete string conversion with mutable cursor, output, state and synchronous decoder service.',
        export_adapters=['adapters/bridge.c'], output=output/'string-conversion',
        **{**environment, 'runtime_files': runtime})
    write_json(output/'preparation.json', dict(seconds=time.monotonic()-started, cases=len(cases),
        sequences_per_returning_case=192, original_sha256=PE, new_tool_internals=False,
        model_seconds=0, solver_seconds=0, strong_qualification=False))
    return output/'string-conversion'


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('original', type=Path); parser.add_argument('output', type=Path)
    args = parser.parse_args(); print(prepare(args.original.resolve(), args.output.resolve()))
