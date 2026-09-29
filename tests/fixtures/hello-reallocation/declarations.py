"""Complete PE32 realloc normalization and errno boundary; lifetime rules assumed."""
from spaghetti_extractor.boundary import BoundarySchemaV1
from spaghetti_extractor.components.interface_package_v5 import ComponentInterfaceIntentV1
from spaghetti_extractor.components.service_authoring import signature


def interface():
    rows = [signature('reallocate', [('block', 'allocation_block'), ('bytes', 'u32')], 'allocation_block'),
            signature('raw_resize', [('block', 'allocation_block'), ('bytes', 'u32')], 'allocation_block'),
            signature('errno_cell', [], 'bytes')]
    for _, sig in rows[:2]:
        sig['parameters'][0]['nullable'] = sig['results'][0]['nullable'] = True
    rows[2][1]['results'][0].update(interpretation='view', access='read_write',
                                 extent=dict(kind='fixed', bytes=4, value_id=None))
    schema = BoundarySchemaV1.create(schema_id='allocation-reallocate', types=[
        dict(id='u8', kind='integer', signed=False, width_bits=8),
        dict(id='u32', kind='integer', signed=False, width_bits=32),
        dict(id='bytes', kind='pointer', pointee_type_id='u8', qualifiers=[]),
        dict(id='allocation_block', kind='opaque', nominal_id='hello.allocation-block'),
        *[row[0] for row in rows]], signatures=[row[1] for row in rows])
    operation = schema.signature_index['reallocate']
    return ComponentInterfaceIntentV1.create(component_id='allocation-reallocate', schema=schema,
        state=[], effects=[], protocol_states=['ready'], initial_protocol_state='ready',
        services=[dict(id=name, signature_id=name, effect_ids=[], interaction_contract_id=contract)
            for name, contract in [('raw_resize', 'msvcrt.realloc'), ('errno_cell', 'msvcrt.errno')]],
        operations=[dict(id='reallocate', signature_id='reallocate', pre_states=['ready'], post_states=['ready'],
            allowed_service_ids=['raw_resize', 'errno_cell'], effect_ids=[],
            source_values=[value.to_payload() for value in (*operation.parameters, *operation.results)],
            projection_entries=[dict(source_id=value.identity,
                target=dict(root=root, value_id=value.identity, fields=[]))
                for root, values in [('parameter', operation.parameters), ('result', operation.results)] for value in values],
            lifecycle_bindings=[], lifecycle_additional_roots=dict(state=[]), checked_interaction_contract_ids=[])])
