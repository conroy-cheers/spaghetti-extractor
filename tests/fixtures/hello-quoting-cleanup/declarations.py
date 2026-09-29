"""Manual boundary for Hello's complete cache cleanup, including its zero return."""
from spaghetti_extractor.boundary import BoundarySchemaV1
from spaghetti_extractor.components.interface_package_v5 import ComponentInterfaceIntentV1
from spaghetti_extractor.components.service_authoring import signature, value


def representation():
    return dict(group=dict(id='hello-quote-cache', label='Shared quote cache C object definitions',
                          members=['quote-slots', 'quote-cleanup']),
        revision='quote-cache-c-objects-v1',
        inputs={'object-source': 'source/quote-objects.h', 'object-header': 'headers/quote-objects.h'})


def interface():
    rows = [signature('cleanup', [], 'u32'),
            signature('release_buffer', [('buffer', 'quote_bytes')], 'unit'),
            signature('release_table', [('table', 'quote_table')], 'unit')]
    rows[1][1]['parameters'][0]['nullable'] = True
    schema = BoundarySchemaV1.create(schema_id='quote-cleanup', types=[
        dict(id='u32', kind='integer', signed=False, width_bits=32), dict(id='unit', kind='void'),
        *[dict(id='quote_'+name, kind='opaque', nominal_id='hello.quote.'+name)
          for name in ('bytes', 'table', 'state')], *[row[0] for row in rows]],
        signatures=[row[1] for row in rows])
    state = value('slots', 'quote_state')
    result = schema.signature_index['cleanup'].results[0]
    services = ['release_buffer', 'release_table']
    return ComponentInterfaceIntentV1.create(component_id='quote-cleanup', schema=schema,
        state=[dict(value=state, initial=None)], effects=[], protocol_states=['ready'],
        initial_protocol_state='ready', services=[dict(id=name, signature_id=name,
            effect_ids=[], interaction_contract_id='hello.preserve-errno-free') for name in services],
        operations=[dict(id='cleanup', signature_id='cleanup', pre_states=['ready'], post_states=['ready'],
            allowed_service_ids=services, effect_ids=[], source_values=[result.to_payload()],
            projection_entries=[dict(source_id=result.identity,
                target=dict(root='result', value_id=result.identity, fields=[]))],
            lifecycle_bindings=[], lifecycle_additional_roots=dict(state=[state]),
            checked_interaction_contract_ids=[])])
