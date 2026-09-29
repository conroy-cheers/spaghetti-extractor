"""Manual complete quoting-engine boundary and synchronous locale services."""
from spaghetti_extractor.boundary import BoundarySchemaV1
from spaghetti_extractor.components.interface_package_v5 import ComponentInterfaceIntentV1
from spaghetti_extractor.components.service_authoring import signature


def interface():
    specs = {
        'buffer': ([('output', 'quote_bytes'), ('capacity', 'u32'), ('argument', 'quote_bytes'),
                    ('argument_size', 'u32'), ('style', 'u32'), ('flags', 'u32'), ('mask', 'quote_mask'),
                    ('left_quote', 'quote_bytes'), ('right_quote', 'quote_bytes')], 'u32'),
        'mb_cur_max': ([], 'u32'),
        'locale_quote': ([('right', 'u32'), ('style', 'u32')], 'quote_bytes'),
        'byte_printable': ([('byte', 'u32')], 'u32'),
        'conversion_reset': ([('conversion', 'quote_conversion')], 'unit'),
        'decode': ([('conversion', 'quote_conversion'), ('argument', 'quote_bytes'),
                    ('offset', 'u32'), ('size', 'u32')], 'u32'),
        'character_printable': ([('character', 'u32')], 'u32'),
        'conversion_initial': ([('conversion', 'quote_conversion')], 'u32'),
        'invalid_style': ([], 'unit'),
    }
    rows = [signature(name, *spec) for name, spec in specs.items()]
    for _, row in rows:
        if row['id'] == 'buffer':
            for value in row['parameters']:
                value['nullable'] = value['id'] in {'output', 'argument', 'left_quote', 'right_quote'}
    types = [dict(id='u32', kind='integer', signed=False, width_bits=32), dict(id='unit', kind='void'),
             *[dict(id='quote_'+name, kind='opaque', nominal_id='hello.quote.'+name)
               for name in ('bytes', 'mask', 'conversion')], *[row[0] for row in rows]]
    schema = BoundarySchemaV1.create(schema_id='quote-buffer', types=types, signatures=[r[1] for r in rows])
    operation = schema.signature_index['buffer']
    services = list(specs)[1:]
    return ComponentInterfaceIntentV1.create(component_id='quote-buffer', schema=schema,
        state=[], effects=[], protocol_states=['ready'], initial_protocol_state='ready',
        services=[dict(id=name, signature_id=name, effect_ids=[], interaction_contract_id='hello.quote.'+name)
                  for name in services],
        operations=[dict(id='buffer', signature_id='buffer', pre_states=['ready'], post_states=['ready'],
            allowed_service_ids=services, effect_ids=[], checked_interaction_contract_ids=[],
            source_values=[v.to_payload() for v in (*operation.parameters, *operation.results)],
            projection_entries=[dict(source_id=v.identity, target=dict(root=root, value_id=v.identity, fields=[]))
                for root, values in [('parameter', operation.parameters), ('result', operation.results)] for v in values],
            lifecycle_bindings=[], lifecycle_additional_roots=dict(state=[]))])
