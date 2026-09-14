"""Body-independent choices for the checked fixed shared-view theorem domain.

Rendering is conditional, like the existing memory-summary renderer. Provider
selection must additionally establish source, service, entry and machine-frame
premises. No renderer output or declared effect is activation authority.
"""

from .bisimulation_shared_model import render_shared_source_model, _matching_state
from .bisimulation_shared_services import shared_service_contract_index, shared_service_admission_lines
from .component_c_v5 import _parameter_type
from .machine_overlay_services_v5 import _c_identifier
from .normal_exit_postconditions import shared_result_postcondition
from .relation_v5 import ComponentRelationIntentV1

SHARED_STRATEGY = 'image-shared-body-free-experiment-v1'


def checked_shared_summary_inputs(*, certificate, artifacts, normal_exit_inputs, proof_artifacts):
    """Bind local substitution premises; actual consumer entry remains required.

    This internal preparation result has no receipt or provider authority. The
    existing proof readers still reject the experimental strategy until caller
    admission and exact model regeneration are integrated there as well.
    """
    from pathlib import Path
    from .bisimulation_shared_services import checked_shared_service_binding
    from .bisimulation_readable_entry import checked_mutable_entry_operations
    from .bisimulation_mutable_machine_frame import checked_mutable_machine_frame_operations
    from .bisimulation_private_frame import checked_private_frame_operations
    from .interface_package_v5 import ComponentInterfaceIntentV1, compile_component_interface_v5
    from .bisimulation_call_entry import checked_mutable_machine_call_entry_inputs

    bound = checked_shared_service_binding(certificate=certificate, artifacts=artifacts,
                                          normal_exit_inputs=normal_exit_inputs)
    proof = normal_exit_inputs['proof_system']['proof']
    runtime_assurance = normal_exit_inputs.get('runtime_assurance')
    models = proof['models']
    authority = models['reference_authority']
    if (models['connected_components'] or authority.get('data_export_anchors') or
            not authority['rules'] or any(rule['kind'] != 'image' or rule['lifetime'] != 'image'
                or rule['locator']['kind'] != 'image_rva' or rule.get('extent_mode', 'fixed') != 'fixed'
                for rule in authority['rules']) or
            any(models.get(key) is not None for key in ('reference_allocation_requirements','reference_runtime_inventory')) or
            any(segment.get('finite_control_route_inventory_sha256') is not None
                for operation in models['operation_models'] for segment in operation['obligation_models'])):
        raise ValueError('shared summary requires a fixed image leaf without allocation or finite-route premises')
    bundle = compile_component_interface_v5(ComponentInterfaceIntentV1.parse(certificate['interface_intent']))
    operations = sorted(certificate['operation_symbols'])
    for operation in operations:
        shared_summary_operation(bundle, operation, certificate['shared_contract'])
    machine = {name: list(checker(proof, artifacts=Path(proof_artifacts), runtime_assurance=runtime_assurance)) for name,checker in (
        ('entry',checked_mutable_entry_operations),('machine_frame',checked_mutable_machine_frame_operations),
        ('private_frame',checked_private_frame_operations))}
    if any(sorted(machine[name]) != operations for name in ('entry','machine_frame')):
        raise ValueError('shared summary lacks retained wider entry or machine-frame evidence')
    entry = checked_mutable_machine_call_entry_inputs(proof_system=normal_exit_inputs['proof_system'],
        binding_intent=normal_exit_inputs['binding'].to_payload(), artifacts=proof_artifacts, runtime_assurance=runtime_assurance)
    return {**bound, 'strategy':SHARED_STRATEGY, 'machine_facts':machine, 'machine_entry_inputs':entry,
            'shared_contract':certificate['shared_contract']}


def shared_summary_operation(bundle, operation_id, contract):
    """Use the source theorem's exact domain and bounds, not a second schema."""
    render_shared_source_model(bundle=bundle, operation_id=operation_id,
        symbol='spx_summary_domain', kind='frame', shared_contract=contract)
    if 'service_contracts' not in contract:
        raise ValueError('shared summary requires selected service premises')
    services = shared_service_contract_index(bundle, contract['service_contracts'])
    intent = ComponentRelationIntentV1.parse(contract['relation_intent'])
    requirement = next(op for op in intent.operations if op['operation_id'] == operation_id)['requirements'][0]
    _, alias, has_zero = shared_result_postcondition(requirement['expression'], bundle=bundle, operation_id=operation_id)
    if has_zero and next(item.value.access for item in bundle.interface.state if item.value.identity == alias) != 'read_write':
        raise ValueError('current-memory summary requires a writable returned state view')
    return alias, services


def current_memory_operations(contract):
    """Identify requested memory facts after the shared domain is checked."""
    intent = ComponentRelationIntentV1.parse(contract['relation_intent'])
    return frozenset(op['operation_id'] for op in intent.operations
                     if op['requirements'][0]['expression']['op'] == 'and')


def shared_summary_choices(*, bundle, operation_id, contract, prefix):
    """Forget internal store history at observable interaction boundaries.

    A fresh arbitrary byte function over the writable union includes every
    framed post-memory, including unchanged bytes. The checked source theorem
    supplies frame, input-dependence and progress; no source store-count budget
    enters the parent model. Calls retain their checked observable bound and
    selected domains. Subsequent bytes and arguments may depend on responses.
    """
    alias, services = shared_summary_operation(bundle, operation_id, contract)
    writable = [item.value for item in bundle.interface.state if item.value.access == 'read_write']
    havoc = [f'      __CPROVER_spx_connected_summary_range(context->services->context, '
             f'{prefix}_state_address_{_c_identifier(value.identity)}[position], UINT32_C({value.extent["bytes"]}));'
             for value in writable]
    lines = ['    uint32_t summary_done = 0U;']
    for _ in range(contract['maximum_calls']):
        choice_type = 'uint8_t' if len(services) <= 255 else 'uint32_t'
        lines += ['    if (!summary_done) {', *havoc, f'      {choice_type} action;',
            '      __CPROVER_havoc_object(&action);',
            f'      __CPROVER_assume(action <= {len(services)}U);',
            '      if (action == 0U) summary_done = 1U;']
        for ordinal, (service_id, (signature, _, _)) in enumerate(services.items(), start=1):
            lines += [f'      if (action == {ordinal}U) {{']
            arguments = []
            for value in signature.parameters:
                name = 'p_' + _c_identifier(value.identity)
                arguments.append(name)
                if value.interpretation == 'view':
                    state = _matching_state(bundle, value)[0]
                    lines += [f'        {_parameter_type(bundle.intent.schema.type_index, value)} {name} = &context->state.{_c_identifier(state.identity)};']
                else:
                    lines += [f'        {_parameter_type(bundle.intent.schema.type_index, value)} {name};',
                              f'        __CPROVER_havoc_object(&{name});']
            lines += shared_service_admission_lines(service_id, services, assume=True)
            lines += [f'        (void)context->services->{_c_identifier(service_id)}(context->services->context, {", ".join(arguments)});',
                      '      }']
        lines += ['    }']
    lines += havoc
    if operation_id in current_memory_operations(contract):
        view = 'context->state.' + _c_identifier(alias)
        extent = next(item.value.extent['bytes'] for item in bundle.interface.state if item.value.identity == alias)
        # Arbitrary final memory plus an arbitrary in-bounds zero covers every
        # post-state satisfying the existential fact. Never retain a particular
        # service's witness or the supplier's bounded internal store history.
        lines += ['    uint32_t zero_offset; __CPROVER_havoc_object(&zero_offset);',
            f'    __CPROVER_assume(zero_offset < UINT32_C({extent}));',
            f'    uint32_t zero_fault = {view}.write({view}.access_context, {view}.base, zero_offset, 1U, 0U);',
            '    __CPROVER_assert(zero_fault == SPX_BOUNDARY_OK, "spx-bisimulation-summary-current-zero-write");',
            '    __CPROVER_assume(zero_fault == SPX_BOUNDARY_OK);']
    return lines
