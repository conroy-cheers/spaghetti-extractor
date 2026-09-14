"""Checked logical admission of selected service domains and byte footprints.

Local source proofs may overapproximate writes within a declared fixed view.
Every selected public-memory footprint must fit that view, and argument domains
must hold at each call. Binding these premises to a paired supplier is separate
from machine call-entry and body-free consumer composition.
"""

from collections.abc import Mapping
import re

from ..artifacts.artifact_set import canonical_sha256_v3
from ..external.argument_domains import checked_argument_domain, word_in_domain
from ..external.terminated_reads import checked_terminated_write
from .bisimulation_call_ranges import checked_call_ranges
from .bisimulation_service_effects import checked_proof_external_effect_contract, checked_proof_external_contract_identity
from .machine_overlay_services_v5 import _c_identifier

_FIELDS = {'service_id','external_effect_contract','external_contract_identity_sha256','abi_sha256'}


def normalize_shared_service_bindings(bundle, bindings):
    """Project semantics from canonical direct bindings; omit physical call sites."""
    if not isinstance(bindings,(list,tuple)) or not bindings:
        raise ValueError('shared source service bindings are absent')
    signatures = {s.identity:bundle.intent.schema.signature_index[s.signature_id] for s in bundle.interface.services}
    result = {}
    for binding in bindings:
        if not isinstance(binding,Mapping) or binding.get('service_id') not in signatures:
            raise ValueError('shared source service binding names a foreign service')
        count = len(signatures[binding['service_id']].parameters)
        if (binding.get('provider_kind') != 'external_call' or
                binding.get('argument_offsets') != list(range(0,4*count,4)) or
                any(binding.get(field) for field in ('argument_transducers','argument_interfaces','out_interfaces','local_cells')) or
                binding.get('result_projection') is not None or binding.get('captured_target_projection') is not None):
            raise ValueError('shared source service requires direct argument and result transport')
        checked_proof_external_effect_contract(binding)
        checked_proof_external_contract_identity(binding)
        row = {key:binding[key] for key in _FIELDS}
        previous = result.setdefault(row['service_id'],row)
        if previous != row:
            raise ValueError('shared source service has inconsistent selected contracts')
    rows = [result[key] for key in sorted(result)]
    shared_service_contract_index(bundle,rows)
    return rows


def shared_service_contract_index(bundle, rows):
    """Validate local premises; identities acquire authority only via binding."""
    signatures = {s.identity:bundle.intent.schema.signature_index[s.signature_id] for s in bundle.interface.services}
    if not isinstance(rows,list) or not rows:
        raise ValueError('shared source selected service contracts are absent')
    result = {}
    for row in rows:
        if (not isinstance(row,Mapping) or set(row) != _FIELDS or row['service_id'] not in signatures or
                row['service_id'] in result or any(not isinstance(row[key],str) or not re.fullmatch('[0-9a-f]{64}',row[key])
                    for key in ('external_contract_identity_sha256','abi_sha256'))):
            raise ValueError('shared source selected service contract fields differ')
        signature = signatures[row['service_id']]
        count = len(signature.parameters)
        payload = checked_proof_external_effect_contract({**row,'provider_kind':'external_call','argument_offsets':list(range(count))})
        written = checked_terminated_write(payload, argument_words=count)
        if (payload.get('argument_words') != count or payload.get('arity') != {'kind':'fixed','words':count} or
                payload.get('disposition') != 'returns' or payload.get('memory_effect') not in {'none','argumentRanges'} or
                payload.get('world_effect') not in {'none','opaqueResources'} or
                payload.get('callback_effect') not in {None,'none'} or payload.get('external_service_protocol') is not None or
                (written is None and payload.get('result_register_relations') != [{'register':'eax','relation':'exact'}])):
            raise ValueError('shared source selected service behavior is unsupported')
        for value in (*signature.parameters,*signature.results):
            if value.interpretation == 'view':
                continue
            typ = bundle.intent.schema.type_index[value.type_id]
            if value.interpretation != 'value' or typ.kind != 'integer' or typ.body.get('width_bits') != 32 or typ.body.get('signed') is not False:
                raise ValueError('shared source selected service requires direct unsigned words or views')
        constraints = checked_argument_domain(payload.get('argument_domain',[]),argument_words=count)
        for constraint in constraints:
            if signature.parameters[constraint['argument_index']].interpretation != 'value':
                raise ValueError('shared source service pointer domains are unsupported')
        ranges = checked_call_ranges({'external_effect_contract':payload,'raw_indices':list(range(count)),'outputs':[],'cell_inputs':[]})
        for footprint in ranges:
            value = signature.parameters[footprint['base']]
            if (value.interpretation != 'view' or value.extent.get('kind') != 'fixed' or value.nullable or
                    footprint['access'] != 'read' and value.access != 'read_write' or
                    footprint['access'] == 'read' and value.access not in {'read','read_write'}):
                raise ValueError('shared source service footprint lacks a compatible declared view')
            for index in re.findall(r'call->arguments\[(\d+)\]',footprint['extent']):
                if signature.parameters[int(index)].interpretation != 'value':
                    raise ValueError('shared source service footprint size is not a scalar')
        if written is not None:
            if len(signature.results) != 1 or signature.results[0].interpretation != 'value':
                raise ValueError('shared written termination requires one unsigned result')
            # Internal lowering metadata, derived from the validated selected
            # contract. It is never accepted as an independently authored fact.
            ranges = tuple({**footprint, 'written_count_capacity': written['capacity_argument']}
                           for footprint in ranges)
        result[row['service_id']] = (signature,constraints,ranges)
    if list(result) != sorted(signatures):
        raise ValueError('shared source selected service coverage is incomplete or unordered')
    return result


def shared_service_admission_lines(service_id, contracts, *, assume=False):
    signature, constraints, ranges = contracts[service_id]
    arguments = ['p_'+_c_identifier(value.identity) for value in signature.parameters]
    lines = []
    def require(predicate, description):
        # A source theorem asserts these obligations. An abstract summary may
        # restrict its arbitrary choices only after that theorem is checked.
        lines.append(f'  __CPROVER_assume({predicate});' if assume else
                     f'  __CPROVER_assert({predicate}, "{description}");')
    for constraint in constraints:
        predicate = word_in_domain(arguments[constraint['argument_index']],constraint)
        require(predicate, 'spx-shared-selected-service-argument-domain')
    for footprint in ranges:
        view = arguments[footprint['base']]
        extent = re.sub(r'call->arguments\[(\d+)\]',lambda match:arguments[int(match[1])],footprint['extent'])
        offset = footprint['offset']
        require(f'UINT64_C({offset}) <= {view}->extent && ({extent}) <= {view}->extent-UINT64_C({offset})',
                'spx-shared-selected-service-footprint')
        if 'written_count_capacity' in footprint:
            require(f'{arguments[footprint["written_count_capacity"]]} != 0U',
                    'spx-shared-selected-service-written-capacity')
    return lines


def checked_shared_service_binding(*, certificate, artifacts, normal_exit_inputs):
    """Bind local service premises to the exact already-proved supplier overlay.

    This proves no callee-entry or summary-substitution rule. Both full local
    evidence and the existing paired proof/overlay derivation are mandatory.
    """
    from pathlib import Path
    from .bisimulation_readonly_evidence import validate_shared_source_contracts
    from .normal_exit_postconditions import checked_normal_exit_view_postconditions
    from .normalized_component import NormalizedComponentContract
    from .machine_overlay_v5 import render_component_machine_overlay_v5
    from .interface_package_v5 import ComponentInterfaceIntentV1, compile_component_interface_v5
    from .binding_intent import ComponentMachineBindingIntentV1
    from ..semantic_objects.object_authority import MachineObjectAuthorityV2

    validate_shared_source_contracts(certificate,artifacts=Path(artifacts))
    facts = checked_normal_exit_view_postconditions(**{**normal_exit_inputs, 'source_summary_artifacts': artifacts})
    proof = normal_exit_inputs['proof_system']['proof']
    bundle = compile_component_interface_v5(ComponentInterfaceIntentV1.parse(normal_exit_inputs['bundle'].intent.to_payload()))
    binding = ComponentMachineBindingIntentV1.parse(normal_exit_inputs['binding'].to_payload())
    if (certificate['interface_sha256'] != proof['world']['bindings']['interface_sha256'] or
            certificate['source_package']['implementation_sha256'] != proof['models']['implementation_sha256'] or
            certificate['source_profile']['receipt_sha256'] != proof['models']['source_profile_sha256'] or
            certificate['shared_contract']['relation_intent'] != normal_exit_inputs['intent'].to_payload()):
        raise ValueError('shared service premise source, interface or relation differs from the paired proof')
    authority = MachineObjectAuthorityV2.parse(proof['models']['reference_authority'])
    overlay = render_component_machine_overlay_v5(bundle=bundle,
        contract=NormalizedComponentContract.create(interface=bundle.interface,machine_semantics=[op.semantics for op in binding.operations]),
        operation_symbols=normal_exit_inputs['operation_symbols'],transfers=normal_exit_inputs['transfers'],
        machine_binding=normal_exit_inputs['machine_binding'],object_authority_rule_ids=[rule.identity for rule in authority.rules],
        resolved_external_environment=normal_exit_inputs.get('resolved_external_environment'))
    selected = normalize_shared_service_bindings(bundle,[row for entry in overlay.entries for row in entry.get('service_bindings',[])])
    if certificate['shared_contract'].get('service_contracts') != selected:
        raise ValueError('shared source service premises differ from the exact selected overlay contracts')
    return {**({'assurance':normal_exit_inputs['runtime_assurance']} if normal_exit_inputs.get('runtime_assurance') is not None else {}),
        'authorizing':False,'summary_composition_authorized':False,
        'source_contract_sha256':certificate['receipt_sha256'],'proof_receipt_sha256':proof['receipt_sha256'],
        'selected_service_contracts_sha256':canonical_sha256_v3(selected),'normal_exit_facts':facts}
