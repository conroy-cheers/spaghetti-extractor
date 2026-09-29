"""Manual boundary for the complete PE32 rpl_mbsrtowcs operation."""
from spaghetti_extractor.boundary import BoundarySchemaV1
from spaghetti_extractor.components.interface_package_v5 import ComponentInterfaceIntentV1
from spaghetti_extractor.components.service_authoring import signature, value


def interface():
    specs = {
        'convert': ([('output', 'mb_word16'), ('input', 'mb_cursor'), ('limit', 'u32'), ('state', 'mb_state')], 'u32'),
        'decode16': ([('output', 'mb_word16'), ('input', 'mb_bytes'), ('size', 'u32'), ('state', 'mb_state')], 'u32'),
        'set_errno': ([('number', 'u32')], 'unit'), 'invalid_state': ([], 'unit'),
    }
    rows = [signature(name, *spec) for name, spec in specs.items()]
    for _, row in rows:
        for item in row['parameters']:
            if item['id'] == 'output' or (row['id'] == 'convert' and item['id'] == 'state'):
                item['nullable'] = True
    schema = BoundarySchemaV1.create(schema_id='string-conversion', types=[
        dict(id='u32', kind='integer', signed=False, width_bits=32), dict(id='unit', kind='void'),
        *[dict(id='mb_'+name, kind='opaque', nominal_id='hello.multibyte.'+name)
          for name in ('bytes', 'state', 'word16', 'cursor')], *[r[0] for r in rows]],
        signatures=[r[1] for r in rows])
    state = [value('implicit', 'mb_state')]
    sig = schema.signature_index['convert']
    return ComponentInterfaceIntentV1.create(component_id='string-conversion', schema=schema,
        state=[dict(value=v, initial=None) for v in state], effects=[], protocol_states=['ready'],
        initial_protocol_state='ready', operations=[dict(id='convert', signature_id='convert',
            pre_states=['ready'], post_states=['ready'], allowed_service_ids=list(specs)[1:],
            effect_ids=[], checked_interaction_contract_ids=[],
            source_values=[v.to_payload() for v in (*sig.parameters, *sig.results)],
            projection_entries=[dict(source_id=v.identity, target=dict(root=root, value_id=v.identity, fields=[]))
                for root, values in [('parameter', sig.parameters), ('result', sig.results)] for v in values],
            lifecycle_bindings=[], lifecycle_additional_roots=dict(state=state))],
        services=[dict(id=name, signature_id=name, effect_ids=[], interaction_contract_id='hello.multibyte.'+name)
                  for name in list(specs)[1:]])
