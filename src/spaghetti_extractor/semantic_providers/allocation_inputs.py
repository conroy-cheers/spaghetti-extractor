"""Canonical direct producer facts for preparing conditional allocation proofs.

This projection is not a native range inventory or a caller/lifetime proof. It
uses the exact transfer plan and selected environment without requiring final
native realization. Indirect, callback and host-entry coverage stay unresolved.
"""

from collections import defaultdict
from collections.abc import Mapping
import re

from ..artifacts.artifact_set import canonical_sha256_v3
from ..components.bisimulation_allocation_classes import allocation_class_requirement
from ..components.bisimulation_support import BisimulationRefinementError
from ..external.lifetime_effects import LifetimeEffectError, checked_lifetime_effect
from ..external.contracts import CheckedExternalSiteContractError, ExternalSiteIdentity
from ..external.import_sites import bind_import_site
from ..external.resolved import ResolvedExternalEnvironmentV1
from ..external.resolved_contract import resolved_import_contract_behavior
from ..transfer.call_sites import external_tail_call


def allocation_producer_inputs(*, authority, transfers, resolved_environment,
                              transfer_plan, module_interface):
    """Project already replayed transfers, retaining incomplete coverage explicitly."""
    requested = defaultdict(list)
    for rule in authority.rules:
        if rule.locator.kind == 'external_allocation':
            requested[rule.locator.identity].append(rule.identity)
    if not requested:
        return None
    transfer_plan_sha256 = transfer_plan.get('plan_sha256')
    transfer_plan_status = transfer_plan.get('status')
    if (not isinstance(transfer_plan_sha256, str) or
            re.fullmatch(r'[0-9a-f]{64}', transfer_plan_sha256) is None or
            transfer_plan_status not in {'complete', 'incomplete'}):
        raise ValueError('allocation producer inputs require their canonical transfer-plan binding')
    environment = ResolvedExternalEnvironmentV1.parse(resolved_environment, module_interface=module_interface)
    pe_sha256 = environment.payload['bindings']['module_pe_sha256']
    if (authority.bindings.get('original_pe_sha256') != pe_sha256 or
            transfer_plan.get('bindings', {}).get('pe_sha256') != pe_sha256):
        raise ValueError('allocation producer inputs name different original modules')
    selected = defaultdict(list)
    for row in environment.payload['machine_import_contracts']:
        contract = row.get('contract')
        payload = contract.get('payload') if isinstance(contract, Mapping) else None
        if isinstance(payload, Mapping) and payload.get('id') in requested:
            selected[payload['id']].append(row)
    classes, by_import, blockers = [], {}, []
    for identity, authority_ids in sorted(requested.items()):
        candidates = selected[identity]
        if len(candidates) != 1 or len(authority_ids) != 1:
            blockers.append({'code': 'allocation_producer_contract_ambiguous' if candidates else
                             'allocation_producer_contract_missing', 'allocation_id': identity,
                             'authority_ids': sorted(authority_ids), 'matching_contracts': len(candidates)})
            continue
        row = candidates[0]
        try:
            behavior = resolved_import_contract_behavior(row)
            ranges = [relation for relation in behavior.result_register_relations
                      if relation.get('relation') == 'dynamic_range_base']
            if (len(ranges) != 1 or ranges[0].get('register') != 'eax' or
                    ranges[0].get('ownership') is None):
                raise CheckedExternalSiteContractError('allocation class needs one checked owned EAX range result')
            key = behavior.identity
            if key in by_import:
                raise CheckedExternalSiteContractError('allocation import is duplicated')
            item = {'allocation_id': identity, 'authority_id': authority_ids[0],
                    'import': key.payload(), 'contract_identity_sha256': behavior.identity_sha256(),
                    'effect_contract': behavior.profile_effect_payload(), 'direct_sites': []}
            effect = checked_lifetime_effect(item['effect_contract'], argument_words=behavior.argument_words)
            item['class_requirement'] = allocation_class_requirement(
                next(rule for rule in authority.rules if rule.identity == authority_ids[0]),
                contract_identity_sha256=behavior.identity_sha256(), effect=effect,
                argument_words=behavior.argument_words)
            by_import[key] = (item, behavior)
            classes.append(item)
        except (CheckedExternalSiteContractError, LifetimeEffectError, BisimulationRefinementError, AttributeError) as exc:
            blockers.append({'code': 'allocation_producer_contract_unsupported',
                             'allocation_id': identity, 'detail': str(exc)})
    indirect, seen, count = [], set(), 0
    for transfer in transfers:
        if transfer.identity in seen:
            raise ValueError('allocation producer input repeats a transfer identity')
        seen.add(transfer.identity)
        count += 1
        tail = external_tail_call(transfer)
        for call in transfer.calls:
            if call.kind == 'indirect_call':
                indirect.append({'unit_id': transfer.identity, 'instruction_rva': call.instruction_rva,
                                 'event_index': call.call_index, 'kind': 'indirect_call'})
                continue
            if call.kind != 'external_call':
                continue
            key = ExternalSiteIdentity.imported({'dll': call.dll, 'symbol': call.symbol, 'ordinal': call.ordinal},
                                                context='allocation producer direct import')
            target = by_import.get(key)
            if target is None:
                continue
            item, behavior = target
            site = {'unit_id': transfer.identity, 'transfer_sha256': transfer.contract_sha256,
                    'instruction_bytes_sha256': transfer.instruction_bytes_sha256,
                    'instruction_rva': call.instruction_rva, 'event_index': call.call_index,
                    'return_rva': call.return_rva, 'transfer_kind': 'jump' if call is tail else 'call'}
            try:
                checked = bind_import_site(behavior, argument_nodes=call.argument_nodes, tail_jump=call is tail)
                site['checked_external_contract'] = checked.payload()
                site['checked_external_contract_sha256'] = canonical_sha256_v3(checked.payload())
            except CheckedExternalSiteContractError as exc:
                site['blocker'] = str(exc)
                blockers.append({'code': 'allocation_producer_site_unqualified',
                                 'allocation_id': item['allocation_id'], **site})
            item['direct_sites'].append(site)
        if transfer.actions and transfer.actions[-1].op == 'outcome_indirect':
            indirect.append({'unit_id': transfer.identity, 'instruction_rva': transfer.rva_start,
                             'kind': 'indirect_jump'})
    for item in classes:
        item['direct_sites'].sort(key=lambda row: (row['unit_id'], row['event_index'], row['instruction_rva']))
        if not item['direct_sites']:
            blockers.append({'code': 'allocation_producer_direct_site_absent', 'allocation_id': item['allocation_id']})
    result = {'authority': False, 'analysis_kind': 'canonical-direct-allocation-producer-inputs',
              'bindings': {'executable_transfer_plan_sha256': transfer_plan_sha256,
                           'transfer_plan_status': transfer_plan_status,
                           'resolved_external_environment_sha256': environment.identity,
                           'machine_object_authority_sha256': authority.authority_sha256},
              'supplied_transfers_scanned': count, 'direct_site_scan_complete': True,
              'resolved_environment_status': environment.payload['status'],
              'producer_set_complete': False, 'native_runtime_inventory': False,
              'caller_ownership_proved': False, 'classes': classes,
              'unresolved_indirect_sites': sorted(indirect, key=lambda row: (row['unit_id'], row['instruction_rva'], row['kind'])),
              'blockers': blockers,
              'remaining_requirements': ['indirect/callback/host-entry producer coverage',
                  'caller ownership and live-instance inventory', 'allocation/release transitions and cross-cut lifetimes',
                  'checked native selector correspondence at realization']}
    return {**result, 'producer_inputs_sha256': canonical_sha256_v3(result)}
