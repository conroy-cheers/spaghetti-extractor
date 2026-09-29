"""Manual free-wrapper boundary; identical to the retained authoring contract."""
from spaghetti_extractor.boundary import BoundarySchemaV1
from spaghetti_extractor.components.interface_package_v5 import ComponentInterfaceIntentV1


def interface():
    common = dict(nullable=False, resource_kind=None, provider_domain=None)
    token = dict(common, id='allocation_token', type_id='u32', interpretation='value', access='none',
                 extent=dict(kind='none', bytes=None, value_id=None))
    cell = dict(common, id='cell', type_id='bytes', interpretation='view', access='read_write',
                extent=dict(kind='fixed', bytes=4, value_id=None))
    schema = BoundarySchemaV1.create(schema_id='preserve-errno-free', types=[
        dict(id='u8', kind='integer', signed=False, width_bits=8),
        dict(id='u32', kind='integer', signed=False, width_bits=32), dict(id='unit', kind='void'),
        dict(id='bytes', kind='pointer', pointee_type_id='u8', qualifiers=[]),
        dict(id='release.fn', kind='function', calling_convention='cdecl',
             parameter_type_ids=['u32'], result_type_id='unit', variadic=False),
        dict(id='errno.fn', kind='function', calling_convention='cdecl',
             parameter_type_ids=[], result_type_id='bytes', variadic=False)], signatures=[
        dict(id='release', function_type_id='release.fn', parameters=[token], results=[]),
        dict(id='errno', function_type_id='errno.fn', parameters=[], results=[cell])])
    return ComponentInterfaceIntentV1.create(component_id='preserve-errno-free', schema=schema,
        state=[], effects=[], protocol_states=['ready'], initial_protocol_state='ready',
        services=[dict(id='errno_cell', signature_id='errno', effect_ids=[], interaction_contract_id='msvcrt.errno'),
                  dict(id='release_allocation', signature_id='release', effect_ids=[], interaction_contract_id='msvcrt.free')],
        operations=[dict(id='release', signature_id='release', pre_states=['ready'], post_states=['ready'],
            allowed_service_ids=['errno_cell', 'release_allocation'], effect_ids=[], source_values=[token],
            projection_entries=[dict(source_id=token['id'], target=dict(root='parameter', value_id=token['id'], fields=[]))],
            lifecycle_bindings=[], lifecycle_additional_roots=dict(state=[]), checked_interaction_contract_ids=[])])
