"""One stateful boundary for complete restartable 16/32-bit conversion operations."""
from spaghetti_extractor.boundary import BoundarySchemaV1
from spaghetti_extractor.components.interface_package_v5 import ComponentInterfaceIntentV1
from spaghetti_extractor.components.service_authoring import signature, value

OPERATIONS = {
    'decode32': ([('output', 'mb_word32'), ('input', 'mb_bytes'), ('size', 'u32'), ('state', 'mb_state')], 'u32'),
    'decode16': ([('output', 'mb_word16'), ('input', 'mb_bytes'), ('size', 'u32'), ('state', 'mb_state')], 'u32'),
    'initial': ([('state', 'mb_state')], 'u32'),
    'reset': ([('state', 'mb_state')], 'unit'),
}
RANGES = {'decode32': [(0x6df3, 0x7211), (0x14658, 0x1465d)],
          'decode16': [(0x7214, 0x7315)], 'initial': [(0x7318, 0x7331)], 'reset': [(0x2b28, 0x2b35)]}
SERVICES = {'charset': ([], 'mb_bytes'), 'lower_decode16': OPERATIONS['decode16'],
            'set_errno': ([('number', 'u32')], 'unit'), 'invalid_state': ([], 'unit')}


def interface():
    rows = [signature(name, *spec) for name, spec in {**OPERATIONS, **SERVICES}.items()]
    for _, row in rows:
        if row['id'] in ('decode32', 'decode16', 'lower_decode16', 'initial'):
            for item in row['parameters']:
                if item['id'] in ('output', 'input', 'state'): item['nullable'] = True
    schema = BoundarySchemaV1.create(schema_id='multibyte-conversion', types=[
        dict(id='u32', kind='integer', signed=False, width_bits=32), dict(id='unit', kind='void'),
        *[dict(id='mb_'+name, kind='opaque', nominal_id='hello.multibyte.'+name)
          for name in ('bytes', 'state', 'word16', 'word32')], *[r[0] for r in rows]],
        signatures=[r[1] for r in rows])
    state = [value(name, 'mb_state') for name in ('implicit32', 'implicit16')]
    operations = []
    for name in OPERATIONS:
        sig = schema.signature_index[name]
        operations.append(dict(id=name, signature_id=name, pre_states=['ready'], post_states=['ready'],
            allowed_service_ids=list(SERVICES), effect_ids=[], checked_interaction_contract_ids=[],
            source_values=[v.to_payload() for v in (*sig.parameters, *sig.results)],
            projection_entries=[dict(source_id=v.identity, target=dict(root=root, value_id=v.identity, fields=[]))
                for root, values in [('parameter', sig.parameters), ('result', sig.results)] for v in values],
            lifecycle_bindings=[], lifecycle_additional_roots=dict(state=state)))
    return ComponentInterfaceIntentV1.create(component_id='multibyte-conversion', schema=schema,
        state=[dict(value=v, initial=None) for v in state], effects=[], protocol_states=['ready'],
        initial_protocol_state='ready', operations=sorted(operations,key=lambda row:row['id']),
        services=[dict(id=name, signature_id=name, effect_ids=[], interaction_contract_id='hello.multibyte.'+name)
                  for name in SERVICES])
