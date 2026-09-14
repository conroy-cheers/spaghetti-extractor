"""Checked fixed-image shared-state supplier premises and actual CALL admission.

Use the existing nested entry contract and paired/source evidence. No new
receipt is issued here. The caller must validate the nested proof first and
establish the emitted stack, view, input-memory and transport assertions.
"""

import json
from collections.abc import Mapping

from .binding_intent import ComponentMachineBindingIntentV1
from .bisimulation_mutable_machine_frame import mutable_machine_state_guarantee
from .bisimulation_shared_model import SHARED_CONTRACT_POLICY
from .bisimulation_shared_services import normalize_shared_service_bindings
from .bisimulation_shared_summary import shared_summary_operation, current_memory_operations
from .interface_package_v5 import ComponentInterfaceIntentV1, compile_component_interface_v5
from .machine_overlay_state_views import checked_state_view, checked_state_view_result
from . import bisimulation_image_frame as image_frame
from .bisimulation_support import PROOF_PRIVATE_STACK_BELOW

STRATEGY = 'image-shared-body-free-v1'
FRAMED_STRATEGY = 'image-shared-framed-body-free-v1'
STRATEGIES = {STRATEGY, FRAMED_STRATEGY}


def shared_boundary_operations(entry, parent_models, *, framed=False):
    """Derive the theorem domain from checked artifacts, never declared flags.

    The paired proof binds the canonical native and typed proof overlays. Their
    checked lowering inventory supplies selected service premises. The same
    state/result selectors used by the guard emitter derive the normal-return
    alias; merely matching pointer words or interface signatures is insufficient.
    Retained model bytes are checked by the entry-contract producer/provider.
    """
    if entry is None:
        return None
    proof = entry['proof_system']['proof']
    models = proof['models']
    certificate = models.get('source_summary_contracts', {}).get('certificate', {})
    if certificate.get('policy') != SHARED_CONTRACT_POLICY:
        return None
    if not parent_models.get('operation_models'):
        return None
    authority = models.get('reference_authority')
    if (models['connected_components'] or not isinstance(authority, Mapping) or not authority.get('rules')
            or (not image_frame.authority_extension(authority, parent_models.get('reference_authority'))
                if framed else authority != parent_models.get('reference_authority')) or authority.get('data_export_anchors')
            or any(rule['kind'] != 'image' or rule['lifetime'] != 'image' or rule['locator']['kind'] != 'image_rva'
                   or rule.get('extent_mode', 'fixed') != 'fixed' for rule in authority['rules'])
            or any(owner.get(key) is not None for owner in ((models,) if framed else (models, parent_models))
                   for key in ('reference_allocation_requirements', 'reference_runtime_inventory'))):
        return None
    if framed and parent_models.get('reference_runtime_inventory') is not None:
        return None
    if framed and parent_models.get('reference_allocation_requirements') is not None and not isinstance(
            parent_models['reference_allocation_requirements'], list):
        return None
    bundle = compile_component_interface_v5(ComponentInterfaceIntentV1.parse(certificate['interface_intent']))
    binding = ComponentMachineBindingIntentV1.parse(entry['binding_intent'])
    if (bundle.interface.interface_sha256 != proof['world']['bindings']['interface_sha256']
            or bundle.interface.schema_sha256 != proof['world']['bindings']['schema_sha256']
            or binding.intent_sha256 != proof['world']['bindings']['binding_intent_sha256']):
        return None
    lowering = models.get('trusted_adapter_lowering')
    if not isinstance(lowering, Mapping) or lowering.get('status') != 'complete':
        return None
    selected = normalize_shared_service_bindings(bundle, [row['checked_binding'] for row in lowering['adapter_plan']])
    contract = certificate['shared_contract']
    if selected != contract.get('service_contracts'):
        return None
    domains = {row['operation_id']: row for row in entry['operations']}
    models_by_id = {row['operation_id']: row for row in models['operation_models']}
    shards = {(row['operation_id'], row['obligation_id']): row for row in proof['shards']}
    rules = {rule['id']: rule for rule in authority['rules']}
    result = []
    for bound in binding.operations:
        operation = bound.semantics
        model = models_by_id[operation.operation_id]
        if (domains[operation.operation_id]['domain'] != 'mutable-wide'
                or framed and not image_frame.guarantee(proof, model)
                or not mutable_machine_state_guarantee(proof, model)
                or any(parent['machine_image'] != model['machine_image'] for parent in parent_models['operation_models'])
                or any(segment.get('finite_control_route_inventory_sha256') is not None
                       or shards[(operation.operation_id, segment['obligation_id'])].get(
                           'mutable_entry_contract', {}).get('result', {}).get('status') != 'satisfied'
                       for segment in model['obligation_models'])):
            return None
        alias, _ = shared_summary_operation(bundle, operation.operation_id, contract)
        projection = operation.machine_projection['operation']
        states = {row['id']: row for row in projection['state']}
        logical = next(row for row in bundle.interface.operations if row.identity == operation.operation_id)
        value = bundle.intent.schema.signature_index[logical.signature_id].results[0]
        output = next(row['projection'] for row in projection['results'] if row['id'] == value.identity)
        selected_state, _, _ = checked_state_view_result(bundle=bundle, value=value,
            projection=output, state_projections=states)
        if selected_state.value.identity != alias:
            return None
        selectors = {row['authority_id']: row['rule_id'] for row in bound.authority['object_authority_selectors']}
        views = []
        for item in bundle.interface.state:
            projected, size, permissions, address = checked_state_view(bundle, item, states[item.value.identity])
            selector = selectors.get(projected['authority']['id'])
            if selector is None and len(rules) == 1:
                selector = next(iter(rules))
            rule = rules.get(selector)
            if rule is None or rule['permissions'] & permissions != permissions:
                return None
            base = model['machine_image']['preferred_base'] + rule['locator']['rva']
            if (address < base or address + size > base + rule['extent']
                    or address != base and not rule['interior_pointers']):
                return None
            views.append({'id': item.value.identity, 'address': address, 'bytes': size,
                          'permissions': permissions, 'selector': selector})
        result.append({'operation_id': operation.operation_id, 'views': views, 'result_state': alias})
    return result


def shared_entry_assertions(connected):
    if connected.get('summary_strategy') not in STRATEGIES:
        return []
    return [f"spx-bisimulation-connected-shared-entry:{connected['component_id']}:{op['operation_id']}"
            for op in connected['entry_contract']['operations']]


def allocation_preserving_dependencies(models):
    """Project local allocation requirements only across checked empty heap frames.

    A framed image leaf may use services, but its checked source/service and
    machine-access premises exclude heap access and lifetime transitions. Its
    caller must still discharge the emitted entry guards. The enclosing proof
    reader validates retained supplier evidence; this predicate issues no proof.
    """
    for row in models.get('connected_components', []):
        if row.get('summary_strategy') == 'scalar-body-free-v1':
            continue
        if row.get('summary_strategy') != FRAMED_STRATEGY:
            return False
        try:
            if shared_boundary_operations(row.get('entry_contract'), models, framed=True) is None:
                return False
            guards = set(shared_entry_assertions(row))
            if any(not guards.issubset(segment['required_assertion_descriptions'])
                   for operation in models['operation_models'] for segment in operation['obligation_models']):
                return False
        except (ValueError, TypeError, KeyError, StopIteration, AttributeError):
            return False
    return True


def shared_entry_checks(row):
    if row.get('summary_strategy') not in STRATEGIES:
        return []
    entry = row['entry_contract']
    framed = row['summary_strategy'] == FRAMED_STRATEGY
    models = entry['proof_system']['proof']['models']
    operations = shared_boundary_operations(entry, models, framed=framed)
    if operations is None:
        raise ValueError('shared composition lacks checked supplier guarantees')
    operation = next(op for op in operations if op['operation_id'] == row['operation_id'])
    if framed:
        domain = next(op for op in entry['operations'] if op['operation_id'] == row['operation_id'])
        model = next(op for op in models['operation_models'] if op['operation_id'] == row['operation_id'])
        image = model['machine_image']
        high = domain['private_high_offset']
        lines = [f'      uint64_t shared_private_low = call_state.esp < {PROOF_PRIVATE_STACK_BELOW}U ? 0U : call_state.esp - {PROOF_PRIVATE_STACK_BELOW}U;',
            '      uint32_t shared_entry = rt->resolve_reference != 0 &&',
            f"          spx_proof_image_private_allocation_frame(&spx_exact_world, UINT32_C({image['preferred_base']}), "
            f"UINT64_C({image['image_size']}), shared_private_low, (uint64_t)call_state.esp + UINT64_C({high}));"]
        if model.get('private_stack_accesses') is not None:
            lines = image_frame.consumer_frame_checks(model, domain, image)
    else:
        lines = ['      uint32_t shared_entry = rt->resolve_reference != 0 && spx_exact_world.allocation_count == 0U;']
    for index, view in enumerate(operation['views']):
        ref = f'shared_reference_{index}'
        lines += [f'      spx_machine_reference_v1 {ref} = {{0}};',
            f"      shared_entry = shared_entry && rt->resolve_reference(rt->context, UINT32_C({view['address']}), "
            f"UINT32_C({view['bytes']}), {view['permissions']}U, {json.dumps(view['selector'])}, 0U, 0U, &{ref}) == SPX_BOUNDARY_OK;",
            f"      shared_entry = shared_entry && {ref}.object != 0U && {ref}.offset <= UINT32_C({view['address']}) && "
            f'{ref}.extent <= UINT32_MAX && {ref}.offset <= {ref}.extent && '
            f"UINT64_C({view['bytes']}) <= {ref}.extent - {ref}.offset && "
            f"UINT64_C({view['address']}) - {ref}.offset != 0U && "
            f"{ref}.extent <= UINT64_C(4294967296) - (UINT64_C({view['address']}) - {ref}.offset);"]
    return lines + [f'      __CPROVER_assert(shared_entry, "spx-bisimulation-connected-shared-entry:{row["component_id"]}:{row["operation_id"]}");',
                    '      __CPROVER_assume(shared_entry);']


def shared_summary_bounds(connected):
    """Parent event budgets depend on public contracts, never source bodies."""
    writes = calls = 0
    for row in connected:
        if row['summary_strategy'] not in STRATEGIES:
            continue
        certificate = row['entry_contract']['proof_system']['proof']['models']['source_summary_contracts']['certificate']
        count = certificate['shared_contract']['maximum_calls']
        writable = sum(item['value']['access'] == 'read_write' for item in certificate['interface_intent']['state'])
        writes += (count + 1) * writable + int(bool(current_memory_operations(certificate['shared_contract'])))
        calls += count
    return writes, calls


def shared_current_memory_summaries(connected):
    return any(row.get('summary_strategy') in STRATEGIES and current_memory_operations(
        row['entry_contract']['proof_system']['proof']['models']['source_summary_contracts']['certificate']['shared_contract'])
        for row in connected)
