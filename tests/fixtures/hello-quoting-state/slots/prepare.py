"""Author the complete real quoting-slot C unit using existing V5 packages.

The logical objects and service refinements are proposals. Compilation and
controlled comparisons do not discharge their representation or lifetime rules.
"""
import argparse
import json
from pathlib import Path
import shutil
import time

from spaghetti_extractor.boundary import BoundarySchemaV1
from spaghetti_extractor.components.component_c_v5 import render_component_c_headers_v5
from spaghetti_extractor.components.interface_package_v5 import ComponentInterfaceIntentV1, compile_component_interface_v5
from spaghetti_extractor.components.service_authoring import signature, value
from spaghetti_extractor.components.source import build_component_source_package
from spaghetti_extractor.operator.source_check import write_component_source_check
from spaghetti_extractor.util import sha256_file, write_json

HERE = Path(__file__).resolve().parent


def interface():
    types = [{'id': 'u8', 'kind': 'integer', 'signed': False, 'width_bits': 8},
        {'id': 'u32', 'kind': 'integer', 'signed': False, 'width_bits': 32}, {'id': 'unit', 'kind': 'void'},
        {'id': 'word_bytes', 'kind': 'pointer', 'pointee_type_id': 'u8', 'qualifiers': []},
        *({'id': 'quote_'+name, 'kind': 'opaque', 'nominal_id': 'hello.quote.'+name}
          for name in ('bytes', 'word', 'mask', 'options', 'table', 'state'))]
    operations = {
        'quote': ([('slot_index', 'u32'), ('argument', 'quote_bytes'), ('argument_size', 'u32'),
                   ('options', 'quote_options')], 'quote_bytes'),
        'errno': ([], 'word_bytes'),
        'grow': ([('table', 'quote_table'), ('count', 'quote_word'), ('additional', 'u32'), ('maximum', 'u32')], 'quote_table'),
        'clear': ([('table', 'quote_table'), ('first', 'u32'), ('count', 'u32')], 'unit'),
        'buffer': ([('output', 'quote_bytes'), ('capacity', 'u32'), ('argument', 'quote_bytes'), ('argument_size', 'u32'),
                    ('style', 'u32'), ('flags', 'u32'), ('mask', 'quote_mask'),
                    ('left_quote', 'quote_bytes'), ('right_quote', 'quote_bytes')], 'u32'),
        'release': ([('buffer', 'quote_bytes')], 'unit'),
        'allocate': ([('size', 'u32')], 'quote_bytes'),
        'invalid': ([], 'unit'),
    }
    rows = [signature(name, *spec) for name, spec in operations.items()]
    errno = next(sig for _, sig in rows if sig['id'] == 'errno')['results'][0]
    errno.update(interpretation='view', access='read_write',
                 extent={'kind': 'fixed', 'bytes': 4, 'value_id': None})
    # The actual operation passes null for a new table and an empty output
    # buffer; quoting delimiters can also be null. These are explicit interface
    # domains, not proof of when a returned/borrowed object is live or readable.
    nullable = {'quote': {'argument', 'options', 'result'}, 'grow': {'table'},
                'buffer': {'output', 'argument', 'left_quote', 'right_quote'},
                'release': {'buffer'}, 'allocate': {'result'}}
    for _, sig in rows:
        for item in (*sig['parameters'], *sig['results']):
            item['nullable'] = item['id'] in nullable.get(sig['id'], set())
    schema = BoundarySchemaV1.create(schema_id='quote-slots', types=[*types, *(r[0] for r in rows)],
                                    signatures=[r[1] for r in rows])
    services = {'errno_cell': ('errno', 'msvcrt.errno'), 'grow_slots': ('grow', 'hello.xpalloc.slot-array'),
        'clear_slots': ('clear', 'msvcrt.memset.slot-array'), 'quote_buffer': ('buffer', 'hello.quote-buffer-restyled'),
        'release_buffer': ('release', 'hello.preserve-errno-free'),
        'allocate_buffer': ('allocate', 'hello.xcharalloc'), 'invalid_slot': ('invalid', 'msvcrt.abort')}
    sig = schema.signature_index['quote']
    state = value('slots', 'quote_state')
    return ComponentInterfaceIntentV1.create(component_id='quote-slots', schema=schema,
        state=[{'value': state, 'initial': None}], effects=[],
        services=[{'id': name, 'signature_id': spec[0], 'effect_ids': [], 'interaction_contract_id': spec[1]}
                  for name, spec in services.items()], protocol_states=['ready'], initial_protocol_state='ready',
        operations=[{'id': 'quote', 'signature_id': 'quote', 'pre_states': ['ready'], 'post_states': ['ready'],
            'allowed_service_ids': list(services), 'effect_ids': [],
            'source_values': [v.to_payload() for v in (*sig.parameters, *sig.results)],
            'projection_entries': [{'source_id': v.identity, 'target': {'root': root, 'value_id': v.identity, 'fields': []}}
                for root, values in [('parameter', sig.parameters), ('result', sig.results)] for v in values],
            'lifecycle_bindings': [], 'lifecycle_additional_roots': {'state': [state]}, 'checked_interaction_contract_ids': []}])


def prepare(out):
    started = time.monotonic(); out.mkdir(parents=True)
    intent = interface(); bundle = compile_component_interface_v5(intent)
    (out/'interface').mkdir()
    write_json(out/'interface/component-interface-intent-v1.json', intent.to_payload())
    headers = out/'headers'; headers.mkdir()
    for name, text in render_component_c_headers_v5(bundle, {'quote': 'quote_slots'}).items():
        (headers/name).write_text(text)
    build_component_source_package(lift_unit_id='quote-slots',
        files={name: HERE/name for name in ('quote-slots.c', 'quote-objects.h')}, shared_inputs={},
        operation_symbols={'quote': 'quote_slots'}, out_dir=out/'source')
    timings = []
    status = write_component_source_check(target_id='gnu-hello', component_id='quote-slots',
        interface_package=out/'interface', source_package=out/'source', out=out/'preparation',
        host_compiler=Path(shutil.which('cc')), pe32_compiler=Path(shutil.which('i686-w64-mingw32-gcc')), timings=timings)
    assert status['status'] == 'complete', status
    record = {'status': 'complete C authoring and host/PE32 preparation only', 'original_equivalence': 'unverified',
        'activation_authorized': False, 'seconds': time.monotonic()-started, 'timings': timings,
        'sources': {name: sha256_file(HERE/name) for name in ('quote-slots.c', 'quote-objects.h')},
        'interface_sha256': sha256_file(out/'interface/component-interface-intent-v1.json'),
        'unproved': ['Persistent typed table, buffer, option and errno representation and alias relations.',
                    'Slot growth, allocation/release lifetime and returned buffer escape.',
                    'Reference transport into the checked scalar rpl_free supplier.',
                    'Nonreturning invalid-slot and allocation-failure outcomes.',
                    'Complete contextual equivalence and native admission.']}
    write_json(out/'validation.json', record)
    return record


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    print(json.dumps(prepare(args.output.resolve())), flush=True)
